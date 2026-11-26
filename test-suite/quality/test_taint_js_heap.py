"""D6 regressions: allocation identity, property writes, aliases and joins."""
from __future__ import annotations

from collections import Counter
import hashlib
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
from ubs_core.io import temporary_directory
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
        with temporary_directory(prefix='ubs-heap-') as scratch:
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

    def assert_runtime_sends(self, source, expected, *, module=False):
        """Use fixed harmless markers to check the independent JS behavior."""
        node = shutil.which('node')
        if node is None:
            return  # The scanner assertions still run without this optional oracle.
        if module:
            fixture = ('const req = {query: {html: "review-input"}}; '
                       'const observed = []; const res = {send(value) { observed.push(value); }};\n')
            command = [node, '--input-type=module', '-e', fixture + source
                       + '\nprocess.stdout.write(JSON.stringify(observed));']
        else:
            # Fixture declarations before source would disable a root directive
            # prologue. Execute the authored script verbatim with injected data.
            fixture = ('const vm = require("node:vm"); const observed = []; '
                       'const context = {req: {query: {html: "review-input"}}, '
                       'res: {send(value) { observed.push(value); }}}; ')
            command = [node, '-e', fixture + 'vm.runInNewContext(' + json.dumps(source)
                       + ', context, {timeout: 5000}); process.stdout.write(JSON.stringify(observed));']
        result = subprocess.run(command,
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

    def test_global_undefined_writes_cannot_suppress_parameter_defaults(self):
        reader = 'function read(value = req.query.html) { return value; } '
        for assignment in ('undefined = "safe";', 'undefined = req.query.html;',
                           '({x: undefined} = {x: "safe"});', '[undefined] = ["safe"];',
                           'undefined ||= "safe";', 'undefined ??= "safe";'):
            for nested in (False, True):
                with self.subTest(assignment=assignment, nested=nested):
                    source = reader + ('function outer() { ' + assignment
                              + ' return read(undefined); } res.send(outer());' if nested
                              else assignment + ' res.send(read(undefined));')
                    self.assert_runtime_sends(source, ['review-input'])
                    self.scan(source, 'xss')
        for declaration in ('let undefined;', 'var undefined;', 'let undefined = "old";'):
            source = (reader + 'function outer() { ' + declaration
                      + ' undefined = "safe"; return read(undefined); } res.send(outer());')
            self.assert_runtime_sends(source, ['safe'])
            self.scan(source)

    def test_global_undefined_assignment_retains_rhs_value_and_effects_once(self):
        source = ('const box = {html: "safe"}; const calls = []; '
                  'function value() { calls.push("once"); box.html = req.query.html; return box.html; } '
                  'const result = (undefined = value()); '
                  'res.send(result); res.send(box.html); res.send(undefined); res.send(calls.length);')
        self.assert_runtime_sends(source, ['review-input', 'review-input', None, 1])
        self.scan(source, 'xss', 'xss')
        source = ('function read(value = req.query.html) { return value; } '
                  'function outer(value = (undefined = "safe"), result = read(undefined)) { '
                  'let undefined = "body"; return result; } res.send(outer());')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan(source, 'xss')

    def test_strict_global_undefined_write_keeps_post_rhs_exception_store(self):
        for initial, rhs, following, expected in (
            ('req.query.html', '"safe"', 'box.html = "safe";', ['review-input']),
            ('"safe"', '(box.html = req.query.html)', 'box.html = "safe";', ['review-input']),
            ('req.query.html', '(box.html = "safe")', 'box.html = req.query.html;', ['safe']),
        ):
            for strict in (False, True):
                with self.subTest(initial=initial, rhs=rhs, strict=strict):
                    source = ('const box = {html: ' + initial + '}; function set() { '
                              + ('"use strict";' if strict else '') + 'undefined = ' + rhs + '; '
                              + following + ' } try { set(); } catch (error) {} res.send(box.html);')
                    actual = expected if strict else ['review-input' if 'req.query.html' in following else 'safe']
                    self.assert_runtime_sends(source, actual)
                    self.scan(source, *(('xss',) if 'review-input' in actual else ()))
        for target in ('({x: undefined} = {x: "safe"})', '[undefined] = ["safe"]'):
            source = ('"use strict"; const box = {html: req.query.html}; try { ' + target
                      + '; box.html = "safe"; } catch (error) {} res.send(box.html);')
            self.assert_runtime_sends(source, ['review-input'])
            self.scan(source, 'xss')
        source = ('const box = {html: req.query.html}; function outer() { "use strict"; '
                  'function set(value = (undefined = (box.html = "safe"))) { box.html = req.query.html; } '
                  'try { set(); } catch (error) {} } outer(); res.send(box.html);')
        self.assert_runtime_sends(source, ['safe'])
        self.scan(source)

    def test_strict_global_undefined_catch_finally_and_inheritance(self):
        for handler, expected in (('catch (error) {}', ['review-input']),
                                  ('catch (error) { box.html = "safe"; }', ['safe'])):
            source = ('const box = {html: req.query.html}; function outer() { "use strict"; '
                      'function set() { undefined = "safe"; box.html = "safe"; } '
                      'try { set(); } ' + handler + ' } outer(); res.send(box.html);')
            self.assert_runtime_sends(source, expected)
            self.scan(source, *(('xss',) if 'review-input' in expected else ()))
        source = ('const box = {html: req.query.html}; function set() { "use strict"; '
                  'try { undefined = "safe"; box.html = "safe"; } finally { res.send(box.html); } } '
                  'try { set(); } catch (error) {}')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan(source, 'xss')
        source = ('"use strict"; const box = {html: req.query.html}; function set() { '
                  'let undefined; undefined = "safe"; box.html = "safe"; } set(); res.send(box.html);')
        self.assert_runtime_sends(source, ['safe'])
        self.scan(source)

    def test_builtin_undefined_logical_writes_preserve_exact_bypass(self):
        for strict in (False, True):
            prefix = '"use strict";' if strict else ''
            source = (prefix + 'const box = {html: req.query.html}; '
                      'undefined &&= (box.html = "safe"); res.send(box.html);')
            self.assert_runtime_sends(source, ['review-input'])
            self.scan(source, 'xss')
            source = (prefix + 'const box = {html: req.query.html}; try { '
                      'undefined &&= (box.html = "ignored"); box.html = "safe"; '
                      '} catch (error) {} res.send(box.html);')
            self.assert_runtime_sends(source, ['safe'])
            self.scan(source)
            for operator in ('||=', '??='):
                source = (prefix + 'const box = {html: "safe"}; try { undefined ' + operator
                          + ' (box.html = req.query.html); box.html = "safe"; '
                          '} catch (error) {} res.send(box.html);')
                expected = ['review-input' if strict else 'safe']
                self.assert_runtime_sends(source, expected)
                self.scan(source, *(('xss',) if strict else ()))

    def test_global_undefined_strictness_requires_a_real_directive(self):
        body = ('const box = {html: req.query.html}; try { undefined = "safe"; '
                'box.html = "safe"; } catch (error) {} res.send(box.html);')
        for prefix in ('"use strict";', '\ufeff"use strict";',
                       '/* before */ "other directive"; "use strict";', '"use strict"\n',
                       '#!/usr/bin/env node\n"use strict";'):
            with self.subTest(prefix=prefix):
                self.assert_runtime_sends(prefix + body, ['review-input'])
                self.scan(prefix + body, 'xss')
        for prefix in ('; "use strict";', '"use strict" + "suffix";',
                       '"use\\x20strict";', 'const ignored = "use strict";',
                       'function before() {} "use strict";', '#!/usr/bin/export\n'):
            with self.subTest(prefix=prefix):
                self.assert_runtime_sends(prefix + body, ['safe'])
                self.scan(prefix + body)

    def test_global_undefined_module_strictness_excludes_property_names(self):
        reader = 'function read(value = req.query.html) { return value; } '
        for expression in ('obj.export', 'obj?.export', 'obj.export()', 'obj.import.meta',
                           'obj.\ufeffexport'):
            source = ('const obj = {export: function() {}, import: {meta: "safe"}}; '
                      + expression + '; ' + reader + 'undefined = "safe"; res.send(read(undefined));')
            self.assert_runtime_sends(source, ['review-input'])
            self.scan(source, 'xss')
        body = ('const box = {html: req.query.html}; try { undefined = "safe"; '
                'box.html = "safe"; } catch (error) {} res.send(box.html);')
        for suffix, prefix in (('mjs', ''), ('js', 'export {}; ')):
            source = prefix + body
            self.assert_runtime_sends(source, ['review-input'], module=True)
            with tempfile.TemporaryDirectory(prefix='ubs-undefined-esm-') as scratch:
                path = Path(scratch) / ('handler.' + suffix)
                path.write_text(source, encoding='utf-8')
                findings = list(taint.run(RunContext(lang='javascript', files=[path])))
            self.assertEqual([item['rule'] for item in findings], ['javascript.taint.xss'])

    def test_global_var_undefined_requires_known_declaration_environment(self):
        source = ('function read(value = req.query.html) { return value; } '
                  'var undefined = "safe"; res.send(read(undefined));')
        self.assert_runtime_sends(source, ['review-input'])
        with self.assertRaisesRegex(taint.AnalysisLimit, 'top-level var undefined'):
            self.scan(source)
        script_commonjs_names = ('var undefined = "safe"; const module = {exports: {}}; '
                                'module.exports.x = 1; function read(value = req.query.html) { return value; } '
                                'res.send(read(undefined));')
        self.assert_runtime_sends(script_commonjs_names, ['review-input'])
        with self.assertRaisesRegex(taint.AnalysisLimit, 'top-level var undefined'):
            self.scan(script_commonjs_names)
        unreachable = ('function read(x=req.query.html){return x} '
                       'function outer(){undefined="safe";return read(undefined)} '
                       'try{res.send(outer());throw 0;var undefined;}catch(error){}')
        self.assert_runtime_sends(unreachable, ['review-input'])
        with self.assertRaisesRegex(taint.AnalysisLimit, 'top-level var undefined'):
            self.scan(unreachable)
        self.assert_runtime_sends(source, ['safe'], module=True)
        for suffix in ('mjs', 'cjs'):
            with tempfile.TemporaryDirectory(prefix='ubs-undefined-var-') as scratch:
                path = Path(scratch) / ('handler.' + suffix)
                path.write_text(source, encoding='utf-8')
                self.assertEqual(list(taint.run(RunContext(lang='javascript', files=[path]))), [])
        for declaration in ('class Handler { set() {', 'const handler = { set() {'):
            source = (declaration + 'undefined = "safe"; res.send(req.query.html); }};')
            with self.assertRaisesRegex(taint.AnalysisLimit, 'unsupported strictness context'):
                self.scan(source)

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

    def test_splice_insertions_and_shifts_reach_aliases(self):
        source = ('const items = ["safe", "tail"]; const alias = items;\n'
                  'alias.splice(0, 1, req.query.html);\n'
                  'res.send(items[0]);\nres.send(items[1]);')
        findings = self.scan(source, 'xss')
        self.assertEqual([finding['line'] for finding in findings], [3])
        self.assert_runtime_sends(source, ['review-input', 'tail'])
        self.scan('const items = ["safe", req.query.html]; '
                  'items.splice(0, 1); res.send(items[0]);', 'xss')
        self.scan('const items = [req.query.html]; '
                  'items.splice(0, 0, "first", "second"); '
                  'res.send(items[0]); res.send(items[1]); res.send(items[2]);', 'xss')

    def test_splice_replacement_and_deletion_clear_only_removed_slots(self):
        self.scan('const items = [req.query.html]; items.splice(0, 1, "safe"); res.send(items[0]);')
        self.scan('const items = [req.query.html, req.query.html]; '
                  'items.splice(0, 1); res.send(items[0]); res.send(items[1]);', 'xss')
        self.scan('const items = [req.query.html]; items.splice(0); res.send(items[0]);')
        self.scan('const items = [req.query.html]; items.splice(); res.send(items[0]);', 'xss')

    def test_splice_literal_ranges_match_native_javascript(self):
        cases = [
            ('0, 1', ['review-input', 'b', 'c']),
            ('1, 0', ['a', 'review-input', 'b', 'c']),
            ('-1, 1', ['a', 'b', 'review-input']),
            ('-99, Infinity', ['review-input']),
            ('99, 9', ['a', 'b', 'c', 'review-input']),
            ('1.9, 1.8', ['a', 'review-input', 'c']),
            ('null, true', ['review-input', 'b', 'c']),
            ('NaN, -1', ['review-input', 'a', 'b', 'c']),
            ('undefined, undefined', ['review-input', 'a', 'b', 'c']),
            ('-Infinity, 1e309', ['review-input']),
        ]
        for bounds, expected in cases:
            with self.subTest(bounds=bounds):
                source = ('const items = ["a", "b", "c"];\n'
                          f'items.splice({bounds}, req.query.html);\n'
                          + '\n'.join(f'res.send(items[{index}]);' for index in range(len(expected))))
                findings = self.scan(source, 'xss')
                self.assertEqual([finding['line'] for finding in findings],
                                 [3 + expected.index('review-input')])
                self.assert_runtime_sends(source, expected)

    def test_splice_returns_fresh_removed_array_with_value_snapshots(self):
        source = ('const items = [req.query.html, "tail"]; const alias = items;\n'
                  'const removed = items.splice(0, 1, "safe");\n'
                  'res.send(removed[0]);\nres.send(alias[0]);\n'
                  'removed[0] = "changed"; res.send(items[0]);')
        findings = self.scan(source, 'xss')
        self.assertEqual([finding['line'] for finding in findings], [3])
        self.assert_runtime_sends(source, ['review-input', 'safe', 'safe'])
        self.scan('const items = [req.query.html]; res.send(items.splice(0, 1)[0]);', 'xss')
        self.scan('const items = [req.query.html]; res.send(items.splice(0, 0).length);')

    def test_splice_preserves_sparse_holes_and_named_properties(self):
        source = ('const items = [, req.query.html, , "tail"]; items.label = "label";\n'
                  'const removed = items.splice(0, 3);\n'
                  'res.send(removed[0]); res.send(removed[1]); res.send(removed[2]);\n'
                  'res.send(items[0]); res.send(items[1]); res.send(items.label);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, [None, 'review-input', None, 'tail', None, 'label'])
        self.scan('const items = [req.query.html]; items["-1"] = req.query.html; '
                  'items.splice(0); res.send(items[0]); res.send(items["-1"]);', 'xss')

    def test_splice_retains_inserted_and_removed_object_identity(self):
        source = ('const value = {html: "safe"}; const items = [value, value];\n'
                  'const removed = items.splice(0, 1);\n'
                  'removed[0].html = req.query.html; res.send(items[0].html);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan('const value = {html: "safe"}; const items = []; '
                  'items.splice(0, 0, value); value.html = req.query.html; res.send(items[0].html);', 'xss')

    def test_splice_helpers_and_sanitizer_domains(self):
        self.scan('function replace(items, value) { return items.splice(0, 1, value); } '
                  'const dirty = [req.query.html]; const clean = ["safe"]; '
                  'const removed = replace(dirty, "safe"); replace(clean, req.query.html); '
                  'res.send(dirty[0]); res.send(removed[0]); res.send(clean[0]);', 'xss', 'xss')
        self.scan('const items = ["safe"]; items.splice(0, 1, DOMPurify.sanitize(req.query.html)); '
                  'res.send(items[0]); eval(items[0]); db.query(items[0]); shell.exec(items[0]);',
                  'eval', 'sql', 'command')

    def test_splice_captures_receiver_and_method_before_arguments(self):
        source = ('let items = ["old"]; const original = items; '
                  'function input() { items = ["new"]; return req.query.html; } '
                  'items.splice(0, 1, input()); res.send(original[0]); res.send(items[0]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'new'])
        source = ('const items = ["old"]; function replacement() {} '
                  'function input() { items.splice = replacement; return req.query.html; } '
                  'items.splice(0, 1, input()); res.send(items[0]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])

    def test_splice_and_copy_within_own_methods_keep_selected_bodies(self):
        for method, arguments in (('splice', '0, 1, req.query.html'), ('copyWithin', '0, 1')):
            with self.subTest(method=method):
                self.scan('const items = ["safe", req.query.html]; '
                          f'items.{method} = function() {{ this[0] = "safe"; return ["safe"]; }}; '
                          f'const result = items.{method}({arguments}); '
                          'res.send(items[0]); res.send(result[0]);')
                self.scan('const items = ["safe"]; '
                          f'items.{method} = function() {{ this[0] = req.query.html; }}; '
                          f'items.{method}({arguments}); res.send(items[0]);', 'xss')
        self.scan('const items = ["safe"]; items.splice = external; delete items.splice; '
                  'items["splice"](0, 1, req.query.html); res.send(items[0]);', 'xss')

    def test_copy_within_overlap_directions_match_native_javascript(self):
        cases = [
            ('[req.query.html, "b", "c"]', '1, 0, 2', ['review-input', 'review-input', 'b']),
            ('["a", "b", req.query.html]', '0, 1', ['b', 'review-input', 'review-input']),
            ('["a", req.query.html, "c"]', '-1, 1, 2', ['a', 'review-input', 'review-input']),
            ('["a", req.query.html, "c"]', '0, -2, -1', ['review-input', 'review-input', 'c']),
            ('["a", req.query.html, "c"]', '0, 2, 1', ['a', 'review-input', 'c']),
            ('[req.query.html, "b", "c"]', '1.9, 0.8, 1.8', ['review-input', 'review-input', 'c']),
        ]
        for initial, bounds, expected in cases:
            with self.subTest(initial=initial, bounds=bounds):
                source = (f'const items = {initial};\nitems.copyWithin({bounds});\n'
                          + '\n'.join(f'res.send(items[{index}]);' for index in range(3)))
                findings = self.scan(source, *('xss' for value in expected if value == 'review-input'))
                self.assertEqual([finding['line'] for finding in findings],
                                 [3 + index for index, value in enumerate(expected) if value == 'review-input'])
                self.assert_runtime_sends(source, expected)

    def test_copy_within_cleanup_and_holes_preserve_length(self):
        self.scan('const items = [req.query.html, "safe"]; '
                  'items.copyWithin(0, 1); res.send(items[0]); res.send(items.length);')
        source = ('const items = [req.query.html, , "safe"]; items.copyWithin(0, 1, 2); '
                  'res.send(items[0]); res.send(items[1]); res.send(items[2]); res.send(items.length);')
        self.scan(source)
        self.assert_runtime_sends(source, [None, None, 'safe', 3])
        self.scan('const items = [req.query.html]; Object.freeze(items); '
                  'items.copyWithin(0, 0, 0); res.send(items[0]);', 'xss')

    def test_copy_within_returns_receiver_and_retains_object_aliases(self):
        source = ('const items = [{html: "safe"}, null]; '
                  'const returned = items.copyWithin(1, 0); '
                  'returned[0].html = req.query.html; res.send(items[1].html);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan('const items = ["safe", req.query.html]; const alias = items; '
                  'alias.copyWithin(0, 1); res.send(items[0]); res.send(alias[0]);', 'xss', 'xss')

    def test_copy_within_helpers_keep_sink_specific_sanitization(self):
        self.scan('function move(items) { return items.copyWithin(0, 1); } '
                  'const items = ["safe", DOMPurify.sanitize(req.query.html)]; '
                  'const result = move(items); res.send(items[0]); eval(result[0]);', 'eval')

    def test_splice_and_copy_within_joined_receivers_do_not_prove_cleanup(self):
        for operation in ('splice(0, 1, "safe")', 'copyWithin(0, 1)'):
            with self.subTest(operation=operation):
                self.scan('const a = [req.query.html, "safe"]; const b = [req.query.html, "safe"]; '
                          f'const items = flag ? a : b; items.{operation}; '
                          'res.send(a[0]); res.send(b[0]);', 'xss', 'xss')
                self.scan('const items = [req.query.html, "safe"]; '
                          f'if (flag) items.{operation}; res.send(items[0]);', 'xss')

    def test_splice_and_copy_within_report_unsupported_coercion(self):
        for operation, reason in (('splice(offset, 1, "safe")', 'Array.splice'),
                                  ('splice(0, count, "safe")', 'Array.splice'),
                                  ('splice(0, 1n, "safe")', 'Array.splice'),
                                  ('copyWithin(offset, 1)', 'Array.copyWithin'),
                                  ('copyWithin(0, 1, offset)', 'Array.copyWithin')):
            with self.subTest(operation=operation):
                self.assert_fill_partial('const items = [req.query.html, "safe"]; '
                                         f'try {{ items.{operation}; }} catch (error) {{}} '
                                         'res.send(items[0]);', 'xss', reason=reason)

    def test_splice_and_copy_within_preserve_descriptor_and_species_limits(self):
        for operation, reason in (('splice(0, 1, "safe")', 'Array.splice'),
                                  ('copyWithin(0, 1)', 'Array.copyWithin')):
            for setup in ('Object.freeze(items);', 'Object.seal(items);',
                          'Object.defineProperty(items, "0", {value: req.query.html, writable: false});',
                          'Object.defineProperty(Array.prototype, "0", {get() { return req.query.html; }});',
                          'external({items});'):
                with self.subTest(operation=operation, setup=setup):
                    self.assert_fill_partial('const items = [req.query.html, "safe"]; '
                                             + setup + f'try {{ items.{operation}; }} catch (error) {{}} '
                                             'res.send(items[0]);', 'xss', reason=reason)
        for setup in ('items.constructor = foreign;', 'Array.prototype.constructor = foreign;',
                      'Object.defineProperty(Array, Symbol.species, {get() { return foreign; }});'):
            with self.subTest(setup=setup):
                self.assert_fill_partial('const items = [req.query.html]; ' + setup
                                         + 'items.splice(0, 1, "safe"); res.send(items[0]);',
                                         'xss', reason='Array.splice')

    def test_splice_and_copy_within_unknown_overrides_cannot_certify_mutations(self):
        for method, args in (('splice', '0, 1, req.query.html'), ('copyWithin', '0, 1')):
            for replacement in (f'items.{method} = external;', f'Array.prototype.{method} = external;'):
                with self.subTest(method=method, replacement=replacement):
                    self.assert_fill_partial('const items = ["safe", req.query.html]; '
                                             + replacement + f'items.{method}({args}); res.send(items[0]);',
                                             reason=f'Array.{method}')

    def test_at_selects_exact_relative_indices_and_truncates_fractions(self):
        for index, expected in (('0', 'review-input'), ('-0.9', 'review-input'),
                                ('-2', 'review-input'), ('-2.9', 'review-input'),
                                ('1', 'safe'), ('1.9', 'safe'), ('-1', 'safe'),
                                ('-1.9', 'safe'), ('true', 'safe'), ('false', 'review-input')):
            with self.subTest(index=index):
                source = ('const items=[req.query.html,"safe"]; '
                          f'res.send(items.at({index}));')
                self.assert_runtime_sends(source, [expected])
                self.scan_sort(source, *(('xss',) if expected == 'review-input' else ()))

    def test_at_defaults_holes_and_out_of_range_values(self):
        for index in ('', 'undefined', 'null', 'NaN'):
            with self.subTest(index=index):
                source = f'const items=[req.query.html]; res.send(items.at({index}));'
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')
        for index in ('1', '-2', 'Infinity', '-Infinity', '1e300', '-1e300'):
            with self.subTest(index=index):
                source = f'const items=[req.query.html]; res.send(items.at({index}));'
                self.assert_runtime_sends(source, [None])
                self.scan_sort(source)
        source = ('const items=[,req.query.html]; '
                  'res.send(items.at(0)); res.send(items.at(-1));')
        self.assert_runtime_sends(source, [None, 'review-input'])
        self.scan_sort(source, 'xss')

    def test_at_retains_borrowed_element_identity_and_clean_siblings(self):
        for spelling in ('items.at(0)', 'items.at(-2)', '[box,other].at(0)', '(items).at(0)',
                         'items["at"](0)'):
            with self.subTest(spelling=spelling):
                source = ('const box={html:"safe"}; const other={html:"safe"}; '
                          'const items=[box,other]; const selected=' + spelling + '; '
                          'selected.html=req.query.html; res.send(box.html); res.send(other.html);')
                self.assert_runtime_sends(source, ['review-input', 'safe'])
                self.scan_sort(source, 'xss')
        source = ('const box={html:"safe"}; const selected=[box].at(0); '
                  'box.html=req.query.html; res.send(selected.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')

    def test_at_local_helper_results_keep_aliases_and_contexts_separate(self):
        source = ('function first(items){return items.at(0);}\n'
                  'function make(value){return [{html:value}];}\n'
                  'const dirty=first(make(req.query.html));\n'
                  'const clean=first(make("safe"));\n'
                  'res.send(dirty.html);\nres.send(clean.html);')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        findings = self.scan_sort(source, 'xss')
        self.assertEqual([(row['line'], row['col']) for row in findings], [(5, 1)])
        source = ('function first(items){return items.at(0);}\n'
                  'const box={html:"safe"}; const selected=first([box]);\n'
                  'selected.html=req.query.html;\nres.send(box.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')

    def test_at_returned_object_property_writes_reach_the_original(self):
        for initial, assigned, expected, rules in (
            ('"safe"', 'req.query.html', ['review-input'], ('xss',)),
            ('req.query.html', '"safe"', ['safe'], ()),
        ):
            for target in ('items.at(0).html', 'items.at(-1)["html"]',
                           '[box].at(0).html', '(items.at(0)).html', 'first(items).html'):
                with self.subTest(initial=initial, assigned=assigned, target=target):
                    source = ('function first(items){return items.at(0);} '
                              'const box={html:' + initial + '}; const items=[box]; '
                              + target + '=' + assigned + '; res.send(box.html);')
                    self.assert_runtime_sends(source, expected)
                    self.scan_sort(source, *rules)

    def test_at_returned_property_writes_keep_evaluation_order_and_bypass(self):
        source = ('const box={html:"safe"}; let items=[box]; const calls=[]; '
                  'function choose(){calls.push("once");return items.at(0);} '
                  'choose().html=(items=[{html:"safe"}],req.query.html); '
                  'res.send(box.html); res.send(items[0].html); res.send(calls.length);')
        self.assert_runtime_sends(source, ['review-input', 'safe', 1])
        self.scan_sort(source, 'xss')
        source = ('const box={html:"safe"}; const items=[box]; '
                  'items.at(0)[(items[0]={html:"safe"},"html")]=req.query.html; '
                  'res.send(box.html); res.send(items[0].html);')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        self.scan_sort(source, 'xss')
        source = ('const box={html:req.query.html}; const items=[box]; '
                  'false && (items.at(0).html="safe"); res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')
        source = ('const box={html:req.query.html}; const items=[box]; '
                  'true ? "unused" : items.at(0).html="safe"; res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')

    def test_at_returned_property_comparisons_execute_receiver_once(self):
        for member in ('choose().html', 'choose()["html"]'):
            for operator in ('==', '===', '!=', '!=='):
                source = ('const calls = []; function choose() { calls.push(req.query.html); '
                          'return {html: "safe"}; } '
                          f'const result = {member} {operator} "safe"; res.send(calls[1]);')
                with self.subTest(member=member, operator=operator):
                    self.assert_runtime_sends(source, [None])
                    self.scan_sort(source)

    def test_at_selected_module_helpers_keep_aliases_and_locations(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-at'
        artifacts.mkdir(parents=True, exist_ok=True)
        project = Path(tempfile.mkdtemp(prefix='modules-', dir=artifacts))
        helper, caller = project / 'helper.mjs', project / 'caller.mjs'
        helper.write_text('export function first(items){return items.at(0);}\n', encoding='utf-8')
        caller.write_text('import {first} from "./helper.mjs";\n'
                          'const box={html:"safe"}; const selected=first([box]);\n'
                          'selected.html=req.query.html;\nres.send(box.html);\n', encoding='utf-8')
        findings = list(taint.scan_project_findings([helper, caller]))
        self.assertEqual([(path.name, rule, line, col) for path, rule, line, col, _ in findings],
                         [('caller.mjs', 'js.taint.xss', 4, 1)], findings)

    def test_at_receiver_and_native_callee_are_captured_before_arguments(self):
        source = ('let items=[req.query.html]; const original=items; '
                  'res.send(items.at(0,(items=["safe"]))); res.send(items.at(0)); '
                  'res.send(original.at(0,original.at=function(){return "safe";})); '
                  'res.send(original.at(0));')
        self.assert_runtime_sends(source, ['review-input', 'safe', 'review-input', 'safe'])
        self.scan_sort(source, 'xss', 'xss')

    def test_at_observes_argument_element_and_length_mutations(self):
        for setup, call, expected in (
            ('const items=["safe"];', 'items.at(0,items[0]=req.query.html)', 'review-input'),
            ('const items=[];', 'items.at(-1,items.push(req.query.html))', 'review-input'),
            ('const items=[req.query.html];', 'items.at(0,items.length=0)', None),
            ('const items=[req.query.html];', 'items.at(0,delete items[0])', None),
        ):
            with self.subTest(call=call):
                source = setup + ' res.send(' + call + ');'
                self.assert_runtime_sends(source, [expected])
                self.scan_sort(source, *(('xss',) if expected == 'review-input' else ()))

    def test_at_joined_receivers_cannot_prove_borrowed_cleanup(self):
        source = ('const box={html:req.query.html}; const other={html:"safe"}; '
                  'const items=flag?[box]:[other]; const selected=items.at(0); '
                  'selected.html="safe"; res.send(box.html);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends('const flag=false; ' + source, ['review-input'])

    def test_at_sanitizer_domains_and_nested_postfix_results(self):
        self.scan_sort('const items=[req.query.html,DOMPurify.sanitize(req.query.html)]; '
                       'res.send(items.at(-1)); eval(items.at(-1)); res.send(items.at(0));', 'eval', 'xss')
        source = ('const items=[["safe"],[req.query.html]]; '
                  'res.send(items.at(-1).at(0)); res.send(items.at(0).at(-1));')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        self.scan_sort(source, 'xss')

    def test_at_native_method_identity_survives_borrowing_and_restoration(self):
        source = ('const saved=Array.prototype.at; const items=[req.query.html]; '
                  'items.read=saved; res.send(items.read(0)); '
                  'items.at=function(){return "safe";}; res.send(items.at(0)); '
                  'items.at=saved; res.send(items.at(0));')
        self.assert_runtime_sends(source, ['review-input', 'safe', 'review-input'])
        self.scan_sort(source, 'xss', 'xss')
        source = ('const items=[req.query.html]; items.at=function(){return "safe";}; '
                  'delete items.at; res.send(items.at(0));')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')
        for expression in ('saved(0)', 'saved.call(items,0)', 'saved.apply(items,[0])',
                           'Array.prototype.at.call(items,0)'):
            with self.subTest(expression=expression):
                self.scan_sort('const items=[req.query.html]; const saved=items.at; '
                               + expression + '; res.send(req.query.html);',
                               'xss', partial='Array.at.*receiver')

    def test_at_unknown_coercion_and_indexed_protocols_remain_incomplete(self):
        for index in ('external', '{valueOf:external}', '0n', '"0"', '...indices'):
            with self.subTest(index=index):
                self.scan_sort('res.send(req.query.html); const items=["safe"]; '
                               f'items.at({index});', 'xss', partial='Array.at')
        for setup in ('Object.freeze(items);',
                      'Object.defineProperty(items,"0",{get(){return req.query.html;}});',
                      'Array.prototype[0]=req.query.html;',
                      'Object.setPrototypeOf(items,foreign);',
                      'items.length=external;'):
            with self.subTest(setup=setup):
                self.scan_sort('res.send(req.query.html); const items=["safe"]; '
                               + setup + 'items.at(0);', 'xss', partial='Array.at')

    def test_at_method_override_and_native_deletion_are_not_bypassed(self):
        for setup in ('items.at=external;', 'Array.prototype.at=external;',
                      'items[key]=external;', 'delete Array.prototype.at;',
                      'delete Array.prototype[key];'):
            with self.subTest(setup=setup):
                self.scan_sort('res.send(req.query.html); const items=["safe"]; '
                               + setup + 'items.at(0);', 'xss', partial='Array.at')
        self.scan_sort('const target={at:function(){return "safe";}}; '
                       'res.send(target.at(req.query.html));')
        self.scan_sort('const target={at:function(){return req.query.html;}}; '
                       'res.send(target.at(0));', 'xss')

    def test_at_sparse_extent_does_not_expand_holes(self):
        self.scan_sort('const items=[req.query.html]; items.length=4294967295; '
                       'res.send(items.at(0)); res.send(items.at(-1)); res.send(items.at(4294967295));',
                       'xss')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_at_public_json_sarif_selection_and_partial(self):
        cases = (
            ('unsafe', 'const box={html:"safe"};\nconst selected=[box].at(-1);\n'
             'selected.html=req.query.html;\nres.send(box.html);\n',
             [('javascript.taint.xss', 4, 1)], False),
            ('clean', 'const items=[req.query.html,"safe"];\nres.send(items.at(-1));\n'
             'res.send(items.at(2));\n', [], False),
            ('partial', 'res.send(req.query.html);\nconst items=["safe"];\n'
             'items.at({valueOf:external});\n', [('javascript.taint.xss', 1, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-at-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Array.at')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_at_public_cache_edits_suppression_and_partial_nonreuse(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-at-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const box={html:"safe"};\nconst selected=[box].at(0);\n'
                  'selected.html=req.query.html;\nres.send(box.html);\n')
        clean = unsafe.replace('selected.html=req.query.html;', 'selected.html="safe";')
        suppressed = unsafe.replace('res.send(box.html);', 'res.send(box.html); // ubs:ignore')
        partial = 'res.send(req.query.html);\nconst items=["safe"]; items.at(external);\n'
        expected = [('javascript.taint.xss', 4, 1)]
        for index, (source, findings, incomplete, cache_hits) in enumerate((
            (unsafe, expected, False, 0), (unsafe, expected, False, 1), (clean, [], False, 0),
            # Restoring the original bytes may reuse their valid cached report.
            (suppressed, [], False, 0), (unsafe, expected, False, 1),
            (partial, [('javascript.taint.xss', 1, 1)], True, 0),
            (partial, [('javascript.taint.xss', 1, 1)], True, 0),
        )):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                report = self.sort_public_report(target, scratch / f'cache-{index}', meta=True,
                                                fmt='json', expected=findings, partial=incomplete,
                                                cache=True, partial_reason='Array.at')
                self.assertEqual(report['profile']['cache_hits'], cache_hits, report)

    def scan_sort(self, source, *rules, partial=None):
        """Retain independent native-sort inputs and completed/partial evidence."""
        artifacts = ROOT / 'test-suite/artifacts/javascript-sort'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix=self._testMethodName + '-', dir=artifacts))
        path = scratch / 'handler.js'
        path.write_text(source + '\n', encoding='utf-8')
        findings, problem = [], None
        try:
            findings.extend(taint.run(RunContext(lang='javascript', files=[path])))
        except taint.AnalysisLimit as exc:
            problem = str(exc)
        receipt = {
            'case': self.id(), 'source': str(path),
            'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'helper_sha256': hashlib.sha256(Path(taint.__file__).read_bytes()).hexdigest(),
            'python': sys.executable, 'findings': findings, 'incomplete': problem,
        }
        (scratch / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
        print(f'[{self.id()}] source={path} incomplete={problem!r}', flush=True)
        if partial is None:
            self.assertIsNone(problem, receipt)
        else:
            self.assertIsNotNone(problem, receipt)
            self.assertRegex(problem, partial)
        self.assertEqual(Counter(row['rule'].removeprefix('javascript.taint.') for row in findings),
                         Counter(rules), receipt)
        for row in findings:
            self.assertEqual(row['path'], str(path.resolve()))
            self.assertEqual(row['severity'], 'critical')
            self.assertGreater(row['line'], 0)
            self.assertGreater(row['col'], 0)
        return findings

    def test_copy_methods_preserve_shared_element_identity(self):
        for method in ('toReversed()', 'toSorted()', 'toSpliced(1,1)', 'with(1,"new")'):
            with self.subTest(method=method):
                initial = '[{html:"safe"}]' if method in {'toReversed()', 'toSorted()'} else '[{html:"safe"},"old"]'
                source = (f'const items={initial}; const copied=items.{method};\n'
                          'copied[0].html=req.query.html;\nres.send(items[0].html);')
                found = self.scan_sort(source, 'xss')
                self.assertEqual([row['line'] for row in found], [3])
                self.assert_runtime_sends(source, ['review-input'])

    def test_concat_preserves_receiver_and_donor_shallow_aliases(self):
        for expression, index in (('items.concat([])', 0), ('["prefix"].concat(items)', 1),
                                  ('items["concat"](items)', 1)):
            with self.subTest(expression=expression):
                source = ('const items=[{html:"safe"}]; const copied=' + expression + ';\n'
                          f'copied[{index}].html=req.query.html;\nres.send(items[0].html);')
                found = self.scan_sort(source, 'xss')
                self.assertEqual([row['line'] for row in found], [3])
                self.assert_runtime_sends(source, ['review-input'])

    def test_concat_creates_fresh_outer_slots_and_scalar_snapshots(self):
        source = ('const items=[req.query.html,"safe"]; const copied=items.concat([]);\n'
                  'items[0]="safe"; copied[1]=req.query.html;\n'
                  'res.send(items[0]); res.send(items[1]);\n'
                  'res.send(copied[0]); res.send(copied[1]);')
        found = self.scan_sort(source, 'xss', 'xss')
        self.assertEqual([row['line'] for row in found], [4, 4])
        self.assert_runtime_sends(source, ['safe', 'safe', 'review-input', 'review-input'])

    def test_concat_keeps_precise_positions_holes_and_named_properties(self):
        source = ('const items=[,"safe"]; items.note=req.query.html;\n'
                  'const donor=[req.query.html,,"tail"]; donor.extra=req.query.html;\n'
                  'const copied=items.concat([],donor);\n'
                  'res.send(copied[0]); res.send(copied[1]);\n'
                  'res.send(copied[2]); res.send(copied[3]); res.send(copied[4]);\n'
                  'res.send(copied.note); res.send(copied.extra); res.send(copied.length);')
        found = self.scan_sort(source, 'xss')
        self.assertEqual([row['line'] for row in found], [5])
        self.assert_runtime_sends(source, [None, 'safe', 'review-input', None, 'tail', None, None, 5])

    def test_concat_appends_plain_objects_and_flattens_arrays_once(self):
        source = ('const item={html:"safe",0:"named",length:1}; const nested=[item];\n'
                  'const copied=[].concat(item,[nested]);\n'
                  'copied[0].html=req.query.html;\n'
                  'res.send(item.html); res.send(copied[1][0].html);\n'
                  'res.send(copied[0][0]); res.send(copied[0].length); res.send(copied.length);')
        self.scan_sort(source, 'xss', 'xss')
        self.assert_runtime_sends(source, ['review-input', 'review-input', 'named', 1, 2])

    def test_concat_primitives_are_single_slots_and_argument_holes_are_undefined(self):
        source = ('const items=[]; const copied=items.concat("word",null,false,undefined,...[,7],[req.query.html]);\n'
                  'res.send(copied[0]); res.send(copied[1]); res.send(copied[2]);\n'
                  'res.send(copied[3]); res.send(copied[4]); res.send(copied[5]);\n'
                  'res.send(copied[6]); res.send(copied.length);')
        found = self.scan_sort(source, 'xss')
        self.assertEqual([row['line'] for row in found], [4])
        self.assert_runtime_sends(source, ['word', None, False, None, None, 7, 'review-input', 7])

    def test_concat_captures_receiver_and_callee_before_argument_effects(self):
        source = ('let items=[{html:"safe"}]; const original=items;\n'
                  'const copied=items.concat((items=["other"]));\n'
                  'copied[0].html=req.query.html;\nres.send(original[0].html); res.send(items[0]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'other'])
        source = ('const items=[req.query.html]; const copied=items.concat((items.concat=()=>["safe"],[]));\n'
                  'res.send(copied[0]); res.send(items.concat()[0]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe'])

    def test_concat_reads_live_array_contents_after_all_arguments(self):
        source = ('const items=[req.query.html]; const donor=["safe"];\n'
                  'const copied=items.concat(donor,(items.fill("safe"),donor[0]=req.query.html,[]));\n'
                  'res.send(copied[0]); res.send(copied[1]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['safe', 'review-input'])

    def test_concat_helpers_and_call_chains_keep_context_and_sanitizer_domains(self):
        source = ('function append(items,extra){return items.concat(extra);}\n'
                  'const box={html:"safe"}; const copied=append([], [box]).concat([]).slice();\n'
                  'copied[0].html=req.query.html;\nres.send(box.html);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort('const dirty=[req.query.html]; const clean=[DOMPurify.sanitize(req.query.html)]; '
                       'const copied=clean.concat(dirty); res.send(copied[0]); res.send(copied[1]); '
                       'eval(copied[0]);', 'xss', 'eval')
        source = ('function copy(items){return items.concat([]);}\n'
                  'const first=copy([{html:"safe"}]); const second=copy([{html:"safe"}]);\n'
                  'first[0].html=req.query.html; res.send(first[0].html); res.send(second[0].html);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe'])

    def test_concat_joined_inputs_preserve_possible_positions_and_aliases(self):
        self.scan_sort('const left=[{html:"safe"}]; const right=[{html:"safe"}]; '
                       'const copied=[].concat(flag?left:right); copied[0].html=req.query.html; '
                       'res.send(left[0].html); res.send(right[0].html);', 'xss', 'xss')
        self.scan_sort('const items=["safe"]; const donor=flag?[]:["other"]; '
                       'const copied=items.concat(donor,[req.query.html]); '
                       'res.send(copied[1]); res.send(copied[2]);', 'xss', 'xss', partial='Array.concat')

    def test_concat_missing_arguments_are_present_undefined_elements(self):
        source = ('const box={}; const copied=[].concat(box.missing,[req.query.html]); '
                  'res.send(copied[0]); res.send(copied[1]); res.send(copied.length);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, [None, 'review-input', 2])
        self.scan_sort('const box={}; if(flag) box.items=[]; '
                       'const copied=[].concat(box.items,[req.query.html]); '
                       'res.send(copied[0]); res.send(copied[1]);', 'xss', 'xss', partial='Array.concat')
        self.scan_sort('const box={}; if(flag) box.items=["safe"]; '
                       'const copied=[].concat(box.items,[req.query.html]); '
                       'res.send(copied[0]); res.send(copied[1]);', 'xss')

    def test_concat_mixed_object_and_primitive_slots_cannot_prove_cleanup(self):
        source = ('const flag=false; const box={html:req.query.html}; '
                  'const copied=[].concat(flag?[box]:["safe"]); '
                  'copied[0].html="safe"; res.send(box.html);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        self.assert_runtime_sends(source.replace('const flag=false;', 'const flag=true;'), ['safe'])
        source = ('const box={html:req.query.html}; const copied=[].concat([box]); '
                  'copied[0].html="safe"; res.send(box.html);')
        self.scan_sort(source)
        self.assert_runtime_sends(source, ['safe'])

    def test_concat_selected_own_methods_keep_their_actual_behavior(self):
        source = ('const items=[req.query.html]; items.concat=function(extra){return ["safe"];}; '
                  'const copied=items.concat([req.query.html]); res.send(copied[0]);')
        self.scan_sort(source)
        self.assert_runtime_sends(source, ['safe'])
        source = ('const items=[{html:"safe"}]; '
                  'items.concat=function(){this[0].html=req.query.html;return this;}; '
                  'items.concat(); res.send(items[0].html);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])

    def test_concat_unknown_extents_spreads_and_shapes_remain_partial(self):
        for call in ('items.concat(unknown)', 'items.concat(...unknown)', 'items.concat(req.query.html)',
                     'items.concat(flag?["safe"]:"safe")'):
            with self.subTest(call=call):
                self.scan_sort('const items=[req.query.html]; const copied=' + call + '; '
                               'res.send(copied[0]);', 'xss', partial='Array.concat')
        self.scan_sort('const items=[req.query.html]; items.length=unknown; '
                       'const copied=items.concat([]); res.send(copied[0]);', 'xss', partial='Array.concat')
        self.scan_sort('const items=flag?[req.query.html]:"safe"; '
                       'const copied=items.concat([]); res.send(copied[0]);', 'xss', partial='Array.concat')

    def test_concat_spreadability_species_and_descriptor_contracts_remain_partial(self):
        for setup in ('items[Symbol.isConcatSpreadable]=false;', 'items.constructor=foreign;',
                      'Array.prototype[Symbol.isConcatSpreadable]=false;',
                      'Object.defineProperty(Array,Symbol.species,{get(){return foreign;}});',
                      'Object.defineProperty(items,"0",{get(){return req.query.html;}});',
                      'Object.setPrototypeOf(items,foreign);', 'Array.prototype[0]=req.query.html;',
                      'items.concat=external;', 'items[key]=external;'):
            with self.subTest(setup=setup):
                self.scan_sort('res.send(req.query.html); const items=["safe"]; '
                               + setup + 'items.concat([]);', 'xss', partial='Array.concat|Object[.]|Own method')
        for setup in ('donor[Symbol.isConcatSpreadable]=false;',
                      'Object.setPrototypeOf(donor,foreign);',
                      'Object.defineProperty(donor,Symbol.isConcatSpreadable,{get(){return true;}});'):
            with self.subTest(donor=setup):
                self.scan_sort('res.send(req.query.html); const items=[]; const donor={html:"safe"}; '
                               + setup + 'items.concat(donor);', 'xss', partial='Array.concat')
        self.scan_sort('const items=[]; const donor=[req.query.html]; donor.constructor=foreign; '
                       'const copied=items.concat(donor); res.send(copied[0]);', 'xss')

    def test_concat_sparse_cost_tracks_stored_slots_and_rejects_length_overflow(self):
        self.scan_sort('const items=[]; items.length=4294967294; items[4294967293]=req.query.html; '
                       'const copied=items.concat(["safe"]); '
                       'res.send(copied[4294967293]); res.send(copied[4294967294]); '
                       'res.send(copied[0]); res.send(copied.length);', 'xss')
        self.scan_sort('const items=[]; items.length=4294967295; items[4294967294]=req.query.html; '
                       'const copied=items.concat(["extra"]); res.send(copied[4294967294]);',
                       'xss', partial='Array.concat.*length')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_concat_public_identity_positions_and_partial_status(self):
        cases = (
            ('alias', 'const items=[{html:"safe"}];\nconst copied=items.concat([]);\n'
             'copied[0].html=req.query.html;\nres.send(items[0].html);\n',
             [('javascript.taint.xss', 4, 1)], False),
            ('clean', 'const items=["safe"];\nconst copied=items.concat([req.query.html]);\n'
             'res.send(copied[0]);\nres.send(copied.length);\n', [], False),
            ('partial', 'res.send(req.query.html);\nconst items=["safe"];\n'
             'items.concat(unknown);\n', [('javascript.taint.xss', 1, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-concat-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Array.concat')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_concat_public_cache_invalidation_and_suppression(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-concat-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const items=[{html:"safe"}];\nconst copied=items.concat([]);\n'
                  'copied[0].html=req.query.html;\nres.send(items[0].html);\n')
        clean = unsafe.replace('copied[0].html=req.query.html;', 'copied[0]={html:req.query.html};')
        suppressed = unsafe.replace('res.send(items[0].html);', 'res.send(items[0].html); // ubs:ignore')
        for index, (source, expected) in enumerate((
                (unsafe, [('javascript.taint.xss', 4, 1)]),
                (unsafe, [('javascript.taint.xss', 4, 1)]),
                (clean, []), (suppressed, []), (unsafe, [('javascript.taint.xss', 4, 1)]))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                        expected=expected, cache=True)

    def test_slice_preserves_shallow_element_aliases(self):
        for call in ('items.slice()', 'alias.slice(1)', 'items["slice"](-1)'):
            with self.subTest(call=call):
                initial = '[{html:"safe"}]' if call == 'items.slice()' else '["skip",{html:"safe"}]'
                index = 0 if call == 'items.slice()' else 1
                source = (f'const items={initial}; const alias=items; const copied={call};\n'
                          f'copied[0].html=req.query.html;\nres.send(items[{index}].html);')
                found = self.scan_sort(source, 'xss')
                self.assertEqual([row['line'] for row in found], [3])
                self.assert_runtime_sends(source, ['review-input'])

    def test_slice_copies_outer_slots_and_snapshots_values(self):
        source = ('const items=["safe"]; const copied=items.slice(); '
                  'copied[0]=req.query.html;\nres.send(items[0]);\nres.send(copied[0]);')
        found = self.scan_sort(source, 'xss')
        self.assertEqual([row['line'] for row in found], [3])
        self.assert_runtime_sends(source, ['safe', 'review-input'])
        source = ('const items=[req.query.html]; const copied=items.slice(); '
                  'items.fill("safe");\nres.send(items[0]);\nres.send(copied[0]);')
        found = self.scan_sort(source, 'xss')
        self.assertEqual([row['line'] for row in found], [3])
        self.assert_runtime_sends(source, ['safe', 'review-input'])

    def test_slice_literal_ranges_preserve_exact_positions(self):
        cases = (
            ('', ['review-input', 'safe', 'review-input', 3]),
            ('1', ['safe', 'review-input', None, 2]),
            ('1,2', ['safe', None, None, 1]),
            ('-2,-1', ['safe', None, None, 1]),
            ('-1', ['review-input', None, None, 1]),
            ('1.9,2.8', ['safe', None, None, 1]),
            ('3,0', [None, None, None, 0]),
            ('-99,99', ['review-input', 'safe', 'review-input', 3]),
            ('null,undefined', ['review-input', 'safe', 'review-input', 3]),
            ('false,true', ['review-input', None, None, 1]),
            ('NaN,Infinity', ['review-input', 'safe', 'review-input', 3]),
            ('1e309', [None, None, None, 0]),
            ('-1e309', ['review-input', 'safe', 'review-input', 3]),
            ('0,NaN', [None, None, None, 0]),
            ('0,null', [None, None, None, 0]),
            ('0,-0.1', [None, None, None, 0]),
            ('(+1),(-1)', ['safe', None, None, 1]),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                source = ('const items=[req.query.html,"safe",req.query.html];\n'
                          f'const copied=items.slice({arguments});\n'
                          'res.send(copied[0]);\nres.send(copied[1]);\n'
                          'res.send(copied[2]);\nres.send(copied.length);')
                found = self.scan_sort(source, *('xss' for value in expected if value == 'review-input'))
                self.assertEqual([row['line'] for row in found],
                                 [3 + index for index, value in enumerate(expected) if value == 'review-input'])
                self.assert_runtime_sends(source, expected)

    def test_slice_preserves_holes_and_skips_absent_callbacks(self):
        source = ('const items=[,"safe",,]; const copied=items.slice(); '
                  'copied.forEach(value=>{res.send(value);}); res.send(copied.length);')
        self.scan_sort(source)
        self.assert_runtime_sends(source, ['safe', 3])
        source = ('const items=[,,]; const copied=items.slice(); let html="safe"; '
                  'copied.forEach(value=>{html=req.query.html;}); res.send(html);')
        self.scan_sort(source)
        self.assert_runtime_sends(source, ['safe'])
        source = ('const items=[,req.query.html,,]; const copied=items.slice(1); '
                  'copied.forEach(value=>{res.send(value);}); '
                  'res.send(copied[1]); res.send(copied.length);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', None, 2])

    def test_slice_keeps_named_properties_out_of_elements(self):
        source = ('const items=["safe"]; items.extra=req.query.html; '
                  'items["-1"]=req.query.html; items["01"]=req.query.html; '
                  'items["4294967295"]=req.query.html; const copied=items.slice(); '
                  'res.send(copied[0]); res.send(copied.extra); res.send(copied["-1"]); '
                  'res.send(copied["01"]); res.send(copied["4294967295"]); res.send(copied.length);')
        self.scan_sort(source)
        self.assert_runtime_sends(source, ['safe', None, None, None, None, 1])

    def test_slice_transports_selected_helper_results_and_captures(self):
        source = ('function copy(items){return items.slice(1);} '
                  'const items=["skip",{html:"safe"}]; const copied=copy(items); '
                  'copied[0].html=req.query.html; res.send(items[1].html); '
                  'res.send(copy([req.query.html,"safe"])[0]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        source = ('function outer(items){function copy(){return items.slice();}return copy();} '
                  'const items=[{html:"safe"}]; const copied=outer(items); '
                  'copied[0].html=req.query.html; res.send(items[0].html);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])

    def test_slice_keeps_selected_own_methods_and_argument_order(self):
        for body, expected, rules in (('return this;', ['review-input'], ('xss',)),
                                      ('return ["safe"];', ['safe'], ())):
            source = ('const items=["safe"]; items.slice=function(){' + body + '}; '
                      'const copied=items.slice(); copied[0]=req.query.html; res.send(items[0]);')
            with self.subTest(body=body):
                self.scan_sort(source, *rules)
                self.assert_runtime_sends(source, expected)
        source = ('const items=[req.query.html]; '
                  'const copied=items.slice(0,undefined,items.slice=function(){return ["safe"];}); '
                  'res.send(copied[0]); res.send(items.slice()[0]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        source = ('const items=[req.query.html]; '
                  'const copied=items.slice(0,undefined,items.fill("safe")); res.send(copied[0]);')
        self.scan_sort(source)
        self.assert_runtime_sends(source, ['safe'])

    def test_slice_composes_literal_receivers_and_postfix_chains(self):
        for source in (
            'res.send(["safe",req.query.html].slice(1)[0]);',
            'const items=["safe",req.query.html]; res.send((items).slice(1)[0]);',
            'function make(){return ["safe",req.query.html];} res.send(make().slice(1).slice()[0]);',
            'const items=["safe",req.query.html]; res.send(items["slice"](1).map(value=>value)[0]);',
        ):
            with self.subTest(source=source):
                self.scan_sort(source, 'xss')
                self.assert_runtime_sends(source, ['review-input'])

    def test_slice_preserves_sanitizer_domains_and_callable_identity(self):
        found = self.scan_sort('const items=[DOMPurify.sanitize(req.query.html)]; '
                               'const copied=items.slice();\nres.send(copied[0]);\neval(copied[0]);', 'eval')
        self.assertEqual([row['line'] for row in found], [3])
        source = ('const items=[function(){return req.query.html;}]; '
                  'const copied=items.slice(); const selected=copied[0]; res.send(selected());')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])

    def test_slice_sparse_extent_cost_tracks_present_slots(self):
        # No dense iteration over four billion absent slots is needed.
        self.scan_sort('const items=[]; items.length=4294967295; items[4294967294]=req.query.html; '
                       'const copied=items.slice(); const tail=copied.slice(-1); '
                       'res.send(copied[4294967294]); res.send(tail[0]); '
                       'res.send(copied[0]); res.send(tail[1]); res.send(copied.length);', 'xss', 'xss')

    def test_slice_unknown_bounds_and_extents_remain_explicit(self):
        for arguments in ('offset', '0,end', '0n', '...bounds', '{valueOf:external}', '"1"'):
            with self.subTest(arguments=arguments):
                self.scan_sort('const items=[req.query.html]; '
                               f'const copied=items.slice({arguments}); res.send(copied[0]);',
                               'xss', partial='Array.slice')
        self.scan_sort('const items=[req.query.html]; items.length=unknown; '
                       'const copied=items.slice(); res.send(copied[0]);', 'xss', partial='Array.slice')

    def test_slice_species_descriptors_and_method_uncertainty_remain_explicit(self):
        for setup in ('items.constructor=foreign;', 'Array.prototype.constructor=foreign;',
                      'Object.defineProperty(Array,Symbol.species,{get(){return foreign;}});',
                      'Object.defineProperty(items,"0",{get(){return req.query.html;}});',
                      'Object.setPrototypeOf(items,foreign);', 'Array.prototype[0]=req.query.html;',
                      'items.slice=external;', 'Array.prototype.slice=external;',
                      'items[key]=external;'):
            with self.subTest(setup=setup):
                self.scan_sort('res.send(req.query.html); const items=["safe"]; '
                               + setup + 'items.slice();', 'xss', partial='Array.slice|Object[.]|Own method')

    def test_slice_array_scalar_alternatives_are_not_guaranteed_arrays(self):
        self.scan_sort('const items=flag ? [req.query.html] : "safe"; '
                       'const copied=items.slice(); res.send(copied[0]);', 'xss', partial='Array.slice')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_slice_public_identity_ranges_and_partial_status(self):
        cases = (
            ('alias', 'const items=[{html:"safe"}];\nconst copied=items.slice();\n'
             'copied[0].html=req.query.html;\nres.send(items[0].html);\n',
             [('javascript.taint.xss', 4, 1)], False),
            ('clean', 'const items=[req.query.html,"safe"];\nconst copied=items.slice(1);\n'
             'res.send(copied[0]);\nres.send(copied.length);\n', [], False),
            ('partial', 'const items=["safe"];\nitems.slice({valueOf:external});\n'
             'res.send(req.query.html);\n', [('javascript.taint.xss', 3, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-slice-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Array.slice')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_slice_public_cache_invalidation_and_suppression(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-slice-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const items=[{html:"safe"}];\nconst copied=items.slice();\n'
                  'copied[0].html=req.query.html;\nres.send(items[0].html);\n')
        clean = unsafe.replace('copied[0].html=req.query.html;', 'copied[0]={html:req.query.html};')
        suppressed = unsafe.replace('res.send(items[0].html);', 'res.send(items[0].html); // ubs:ignore')
        for index, (source, expected) in enumerate((
                (unsafe, [('javascript.taint.xss', 4, 1)]),
                (unsafe, [('javascript.taint.xss', 4, 1)]),
                (clean, []), (suppressed, []), (unsafe, [('javascript.taint.xss', 4, 1)]))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                        expected=expected, cache=True)

    def test_copy_methods_create_fresh_containers_with_snapshot_values(self):
        for method in ('toReversed()', 'toSorted()', 'toSpliced()', 'with(1,"safe")'):
            with self.subTest(method=method):
                source = ('const items=["safe","safe"]; '
                          f'const copied=items.{method}; copied[0]=req.query.html;\n'
                          'res.send(items[0]);\nres.send(copied[0]);')
                found = self.scan_sort(source, 'xss')
                self.assertEqual([row['line'] for row in found], [3])
                self.assert_runtime_sends(source, ['safe', 'review-input'])
                source = ('const items=[req.query.html,req.query.html]; '
                          f'const copied=items.{method}; items.fill("safe");\n'
                          'res.send(items[0]);\nres.send(copied[0]);')
                found = self.scan_sort(source, 'xss')
                self.assertEqual([row['line'] for row in found], [3])
                self.assert_runtime_sends(source, ['safe', 'review-input'])

    def test_copy_methods_do_not_mutate_source_or_copy_named_properties(self):
        for method in ('toReversed()', 'toSorted()', 'toSpliced(0,1)', 'with(0,"safe")'):
            with self.subTest(method=method):
                source = ('const items=[req.query.html,"safe"]; items.extra=req.query.html; '
                          f'const copied=items.{method};\n'
                          'res.send(items[0]);\nres.send(copied.extra);\nres.send(copied.length);')
                found = self.scan_sort(source, 'xss')
                self.assertEqual([row['line'] for row in found], [2])
                length = 1 if method == 'toSpliced(0,1)' else 2
                self.assert_runtime_sends(source, ['review-input', None, length])

    def test_copy_reversed_slots_and_spliced_insertions_have_exact_locations(self):
        cases = (
            ('["safe",req.query.html]', 'toReversed()', ['review-input', 'safe']),
            ('[req.query.html,"safe"]', 'toSpliced(0,1)', ['safe', None]),
            ('["safe","old"]', 'toSpliced(-1,1,req.query.html)', ['safe', 'review-input']),
            ('["safe"]', 'toSpliced(0,0,req.query.html)', ['review-input', 'safe']),
            ('[req.query.html,"safe"]', 'with(-2,"clean")', ['clean', 'safe']),
            ('["safe","old"]', 'with(-1,req.query.html)', ['safe', 'review-input']),
            ('[req.query.html,"safe"]', 'with(null,"clean")', ['clean', 'safe']),
        )
        for initial, method, expected in cases:
            with self.subTest(initial=initial, method=method):
                source = (f'const items={initial}; const copied=items.{method};\n'
                          'res.send(copied[0]);\nres.send(copied[1]);')
                found = self.scan_sort(source, *('xss' for value in expected if value == 'review-input'))
                self.assertEqual([row['line'] for row in found],
                                 [2 + index for index, value in enumerate(expected) if value == 'review-input'])
                self.assert_runtime_sends(source, expected)

    def test_copy_methods_densify_holes_before_callbacks(self):
        for method in ('toReversed()', 'toSorted()', 'toSpliced()', 'with(0,undefined)'):
            with self.subTest(method=method):
                source = (f'const copied=[,].{method}; '
                          'const box={html:"safe"}; '
                          'copied.flatMap(value=>{box.html=req.query.html;return [];}); '
                          'res.send(box.html);')
                self.scan_sort(source, 'xss')
                self.assert_runtime_sends(source, ['review-input'])

    def test_copy_methods_retain_sink_specific_sanitization(self):
        for method in ('toReversed()', 'toSorted()', 'toSpliced()', 'with(1,"safe")'):
            with self.subTest(method=method):
                self.scan_sort('const items=[DOMPurify.sanitize(req.query.html),DOMPurify.sanitize(req.query.html)]; '
                               f'const copied=items.{method}; res.send(copied[0]); eval(copied[0]);', 'eval')

    def test_copy_methods_preserve_helper_and_joined_receiver_identity(self):
        source = ('function duplicate(items){return items.toReversed();}\n'
                  'const a=[{html:"safe"}]; const b=[{html:"safe"}];\n'
                  'const copied=duplicate(a); copied[0].html=req.query.html;\n'
                  'res.send(a[0].html);\nres.send(b[0].html);')
        found = self.scan_sort(source, 'xss')
        self.assertEqual([row['line'] for row in found], [4])
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        self.scan_sort('const a=[{html:"safe"}]; const b=[{html:"safe"}]; '
                       'const selected=flag?a:b; const copied=selected.toReversed(); '
                       'copied[0].html=req.query.html; res.send(a[0].html); res.send(b[0].html);',
                       'xss', 'xss')

    def test_copy_methods_capture_receiver_before_argument_rebinding(self):
        source = ('let items=["safe","old"]; const original=items; '
                  'const copied=items.with(1,req.query.html,(items=["new"])); '
                  'res.send(original[1]); res.send(copied[1]); res.send(items[0]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['old', 'review-input', 'new'])
        self.scan_sort('const items=["safe"]; const copied=items.toReversed(req.query.html); '
                       'res.send(copied[0]);')

    def test_copy_methods_support_literal_return_and_copy_chains(self):
        for source in (
            'res.send(["safe",req.query.html].toReversed()[0]);',
            'function make(){return ["safe",req.query.html];} res.send(make().toReversed()[0]);',
            'const items=["safe",req.query.html]; res.send((items).toReversed()[0]);',
            'res.send(["safe",req.query.html].with(0,"new").toReversed()[0]);',
            'res.send(["safe"].toSpliced(0,0,req.query.html).with(1,"new")[0]);',
        ):
            with self.subTest(source=source):
                self.scan_sort(source, 'xss')
                self.assert_runtime_sends(source, ['review-input'])

    def test_copy_methods_keep_selected_own_methods_and_reject_unknown_overrides(self):
        for method in ('toReversed', 'toSorted', 'toSpliced', 'with'):
            with self.subTest(method=method):
                source = ('const items=["safe"]; '
                          f'items.{method}=function(){{return this;}}; '
                          f'const copied=items.{method}(); copied[0]=req.query.html; '
                          'res.send(items[0]);')
                self.scan_sort(source, 'xss')
                self.assert_runtime_sends(source, ['review-input'])
                for setup in (f'items.{method}=external;', f'Array.prototype.{method}=external;',
                              'items[key]=external;'):
                    self.scan_sort('const items=[req.query.html]; ' + setup
                                   + f'items.{method}(); res.send(items[0]);',
                                   'xss', partial=f'Array.{method}')

    def test_copy_sorted_skips_singleton_comparator_and_keeps_callback_boundaries(self):
        source = ('const box={html:"safe"}; const items=[,"safe"]; '
                  'const copied=items.toSorted((a,b)=>{box.html=req.query.html;return 0;}); '
                  'res.send(box.html); res.send(copied[0]); res.send(copied[1]);')
        self.scan_sort(source)
        self.assert_runtime_sends(source, ['safe', 'safe', None])
        source = ('const box={html:"safe"}; const items=["b","a"]; '
                  'items.toSorted((a,b)=>{box.html=req.query.html;return 0;}); res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, partial='Array.toSorted.*comparator')
        for comparator in ('null', 'external', '...comparators'):
            self.scan_sort(f'const items=[]; try{{items.toSorted({comparator});}}catch(error){{}} '
                           'res.send(req.query.html);', 'xss', partial='Array.toSorted.*comparator')

    def test_copy_methods_do_not_hide_coercion_descriptor_or_budget_limits(self):
        for method in ('with(offset,"safe")', 'with(8,"safe")', 'toSpliced(offset,1)',
                       'toSpliced(0,count)', 'with(0n,"safe")'):
            with self.subTest(method=method):
                self.scan_sort('const items=[req.query.html]; '
                               f'try{{items.{method};}}catch(error){{}} res.send(items[0]);',
                               'xss', partial='Array.(with|toSpliced)')
        for method in ('toReversed()', 'toSorted()', 'toSpliced()', 'with(0,"safe")'):
            with self.subTest(method=method):
                self.scan_sort('const items=[req.query.html]; '
                               'Object.defineProperty(items,"0",{get(){return req.query.html;}}); '
                               f'items.{method}; res.send(req.query.html);', 'xss', partial='Array.')
                self.scan_sort('const items=[req.query.html]; items.length=4294967295; '
                               f'items.{method}; res.send("safe");', partial='work limit')
        self.scan_sort('const items=["safe",{html:req.query.html}]; '
                       'const copied=items.toSorted(); res.send(copied[0].html);',
                       'xss', partial='Array.toSorted.*coercion')

    def test_sort_moves_source_through_ignored_calls_and_aliases(self):
        for call in ('items.sort()', 'alias.sort()', 'alias["sort"]()'):
            with self.subTest(call=call):
                source = ('const items=["zz-clean",req.query.html]; const alias=items;\n'
                          + call + ';\nres.send(items[0]);')
                found = self.scan_sort(source, 'xss')
                self.assertEqual(found[0]['line'], 3)
                self.assert_runtime_sends(source, ['review-input'])

    def test_sort_preserves_returned_receiver_and_definite_cleanup(self):
        self.scan_sort('const items=["zz-clean",req.query.html]; const alias=items.sort(); '
                       'alias[0]="safe"; res.send(items[0]); res.send(items[1]);', 'xss')
        self.scan_sort('const items=["zz-clean",req.query.html]; const alias=items.sort(); '
                       'alias.fill("safe"); res.send(items[0]); res.send(items[1]);')
        self.scan_sort('const items=["zz-clean",req.query.html]; res.send(items.sort().length);')

    def test_sort_compacts_sparse_values_and_preserves_trailing_holes(self):
        source = ('const items=[,,req.query.html,,]; items.sort(); '
                  'res.send(items[0]); res.send(items[1]); res.send(items[3]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', None, None])
        self.scan_sort('const items=[,,]; items.sort(); res.send(items[0]);')

    def test_sort_keeps_named_fields_out_of_indexed_values(self):
        for key in ('extra', '-1', '01', '4294967295'):
            with self.subTest(key=key):
                source = (f'const items=["safe"]; items["{key}"]=req.query.html; '
                          f'items.sort(); res.send(items[0]); res.send(items["{key}"]);')
                self.scan_sort(source, 'xss')
                self.assert_runtime_sends(source, ['safe', 'review-input'])

    def test_sort_local_summaries_preserve_caller_and_nested_aliases(self):
        source = ('function order(items){return items.sort();}\n'
                  'const box={items:["zz-clean",req.query.html]};\n'
                  'const alias=order(box.items);\n'
                  'res.send(box.items[0]);\nres.send(alias[0]);')
        found = self.scan_sort(source, 'xss', 'xss')
        self.assertEqual([row['line'] for row in found], [4, 5])
        self.assert_runtime_sends(source, ['review-input', 'review-input'])
        self.scan_sort('function order(items){return items.sort();} '
                       'const dirty=["zz-clean",req.query.html]; const clean=["b","a"]; '
                       'order(dirty); order(clean); res.send(dirty[0]); res.send(clean[0]);', 'xss')

    def test_sort_retains_sink_specific_sanitization(self):
        self.scan_sort('const items=["zz-clean",DOMPurify.sanitize(req.query.html)]; '
                       'items.sort(); res.send(items[0]); eval(items[0]);', 'eval')
        self.scan_sort('const items=["b","a"]; items.sort(); res.send(items[0]);')

    def test_sort_joined_and_conditional_targets_do_not_prove_cleanup(self):
        self.scan_sort('const a=[,"safe",req.query.html]; const b=["safe"]; '
                       'const target=flag?a:b; target.sort(); res.send(a[0]); res.send(a[2]);', 'xss', 'xss')
        self.scan_sort('const items=[,,req.query.html]; if(flag){items.sort();} '
                       'res.send(items[0]); res.send(items[2]);', 'xss', 'xss')

    def test_sort_uses_captured_receiver_after_argument_effects(self):
        source = ('let items=["zz-clean","safe"]; const original=items; '
                  'items.sort(undefined, (items=["new"]), (original[1]=req.query.html)); '
                  'res.send(original[0]); res.send(items[0]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'new'])
        self.scan_sort('const items=["safe"]; items.sort(undefined, req.query.html); res.send(items[0]);')

    def test_sort_empty_and_singleton_skip_comparators_and_conversion(self):
        for initializer, expected in (('[]', [None]), ('["safe"]', ['safe']), ('[,"safe"]', ['safe'])):
            with self.subTest(initializer=initializer):
                source = ('const items=' + initializer + '; const box={html:"safe"}; '
                          'items.sort((a,b)=>{box.html=req.query.html;return 0;}); '
                          'res.send(items[0]); res.send(box.html);')
                self.scan_sort(source)
                self.assert_runtime_sends(source, expected + ['safe'])
        source = ('const box={html:"safe"}; '
                  'const item={toString(){box.html=req.query.html;return "x";}}; '
                  'const items=[,item]; const result=items.sort(); result[0].value=req.query.html; '
                  'res.send(item.value); res.send(box.html);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe'])

    def test_sort_selected_own_methods_keep_their_actual_behavior(self):
        self.scan_sort('const items=["safe"]; items.sort=function(value){return "clean";}; '
                       'res.send(items.sort(req.query.html));')
        source = ('const items=["safe"]; items.sort=function(){this[0]=req.query.html;return this;}; '
                  'const alias=items.sort(); res.send(items[0]); res.send(alias[0]);')
        self.scan_sort(source, 'xss', 'xss')
        self.assert_runtime_sends(source, ['review-input', 'review-input'])
        self.scan_sort('const items=["zz-clean",req.query.html]; items.sort=function(){return "safe";}; '
                       'delete items.sort; items.sort(); res.send(items[0]);', 'xss')

    def test_sort_callback_effects_and_unknown_comparators_are_incomplete(self):
        source = ('const box={html:"safe"}; const items=["b","a"]; '
                  'items.sort((a,b)=>{box.html=req.query.html;return 0;}); res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, partial='Array.sort.*comparator')
        for comparator in ('external', 'null', 'req.query.compare', '...comparators'):
            with self.subTest(comparator=comparator):
                self.scan_sort('const items=["zz-clean",req.query.html]; '
                               'try{items.sort(' + comparator + ');}catch(error){} res.send(items[1]);',
                               'xss', partial='Array.sort.*comparator')

    def test_sort_object_conversion_is_incomplete_and_keeps_other_findings(self):
        source = ('const box={html:"safe"}; const items=["b",'
                  '{toString(){box.html=req.query.html;return "a";}}]; '
                  'items.sort(); res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, partial='Array.sort.*coercion')
        self.scan_sort('const items=[{html:req.query.html},"safe"]; '
                       'items.sort(); res.send(items[0].html);', 'xss', partial='Array.sort.*coercion')

    def test_sort_descriptor_prototype_and_unknown_method_boundaries(self):
        for setup in ('Object.freeze(items);', 'Object.seal(items);',
                      'Object.defineProperty(items,"0",{get(){return req.query.html;}});',
                      'Object.setPrototypeOf(items,foreign);'):
            with self.subTest(setup=setup):
                self.scan_sort('const items=["safe",req.query.html]; ' + setup
                               + 'try{items.sort();}catch(error){} res.send(items[1]);',
                               'xss', partial='Array.sort')
        for setup in ('items.sort=external;', 'Array.prototype.sort=external;',
                      'items[key]=external;'):
            with self.subTest(setup=setup):
                self.scan_sort('const items=["safe",req.query.html]; ' + setup
                               + 'items.sort(); res.send(items[1]);', 'xss', partial='Array.sort')

    def test_sort_sparse_maximum_length_never_expands_holes(self):
        self.scan_sort('const items=[req.query.html]; items.length=4294967295; '
                       'items.sort(); res.send(items[0]); res.send(items[4294967294]);', 'xss')

    def test_sort_literal_receivers_and_returned_array_chains(self):
        for source in (
            'res.send(["zz-clean",req.query.html].sort()[0]);',
            'const items=["zz-clean",req.query.html]; (items).sort(); res.send(items[0]);',
            'function make(){return ["zz-clean",req.query.html];} res.send(make().sort()[0]);',
            'const items=["zz-clean",req.query.html]; res.send(items.sort().sort()[0]);',
            'const items=["zz-clean",req.query.html]; '
            'res.send(items.flatMap(value=>[value]).sort()[0]);',
        ):
            with self.subTest(source=source):
                self.scan_sort(source, 'xss')
                self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort('res.send(["safe"].sort().flatMap(value=>[value])[0]);')

    def test_sort_skipped_callback_sinks_and_unproven_empty_comparators(self):
        for elements in ('[]', '["safe"]', '[,"safe"]'):
            with self.subTest(elements=elements):
                source = (f'const items={elements}; '
                          'items.sort((a,b)=>{res.send(req.query.html);return 0;});')
                self.scan_sort(source)
                self.assert_runtime_sends(source, [])
        for comparator in ('null', 'external', 'req.query.compare'):
            with self.subTest(comparator=comparator):
                self.scan_sort('const items=[]; try{items.sort(' + comparator + ');}catch(error){} '
                               'res.send(req.query.html);', 'xss', partial='Array.sort.*comparator')

    def test_sort_unknown_extent_and_inherited_indices_remain_incomplete(self):
        for setup in ('items.length=unknown;', 'Array.prototype[0]=req.query.html;',
                      'Object.prototype[0]=req.query.html;'):
            with self.subTest(setup=setup):
                self.scan_sort('const items=[,"safe",req.query.html]; ' + setup
                               + 'items.sort(); res.send(items[2]);', 'xss', partial='Array.sort')

    def test_sort_captures_method_identity_and_undefined_arguments(self):
        source = ('const items=["zz-clean",req.query.html]; const skip=undefined; '
                  'items.sort(skip, (items.sort=function(){return "clean";})); '
                  'res.send(items[0]); res.send(items.sort());')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'clean'])
        self.scan_sort('const items=["zz-clean",req.query.html]; '
                       'items.sort(...[undefined]); res.send(items[0]);', 'xss')

    def test_sort_optional_clean_slots_still_contribute_to_possible_extent(self):
        source = ('const items=[,"bb",req.query.html]; if(flag){items[0]="aa";} '
                  'items.sort(); res.send(items[2]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends('const flag=true; ' + source, ['review-input'])
        source = ('const items=["aa","bb",req.query.html]; if(flag){delete items[0];} '
                  'items.sort(); res.send(items[2]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends('const flag=false; ' + source, ['review-input'])

    def sort_public_report(self, target, artifact, *, meta, fmt, expected, partial=False, cache=False,
                           partial_reason='Array.sort'):
        command = ROOT / ('ubs' if meta else 'modules/ubs-js.sh')
        arguments = [str(command), str(target), '--no-color', '--ci', f'--format={fmt}']
        if meta:
            arguments.append('--only=js')
        result = subprocess.run(arguments, cwd=target.parent,
                                env={**os.environ, 'UBS_KEEP_TEMP': '1', 'UBS_NO_AUTO_UPDATE': '1',
                                     'UBS_NO_CACHE': '0' if cache else '1',
                                     'UBS_CACHE_DIR': str(target.parent / 'cache'), 'UBS_PROFILE': '1'},
                                capture_output=True, text=True, timeout=45)
        artifact.with_suffix('.stdout').write_text(result.stdout, encoding='utf-8')
        artifact.with_suffix('.stderr').write_text(result.stderr, encoding='utf-8')
        self.assertEqual(result.returncode, 2 if partial else (1 if expected else 0),
                         (arguments, result.stdout, result.stderr))
        report = json.loads(result.stdout)
        if fmt == 'json':
            self.assertEqual(report['status'], 'partial' if partial else 'ok', report)
            records = report.get('findings', [])
            rule_key, path_key = ('rule_id', 'file') if meta else ('rule', 'path')
            observed = [(row[rule_key], row['line'], row['col']) for row in records]
            self.assertEqual(observed, expected, report)
            totals = report['totals'] if meta else report
            self.assertEqual([totals[key] for key in ('files', 'critical', 'warning', 'info')],
                             [1, len(expected), 0, 0], report)
            for row in records:
                self.assertEqual(Path(row[path_key]).name, target.name, row)
                self.assertEqual(row['severity'], 'critical', row)
                self.assertFalse(row.get('suppressed', False), row)
            if partial:
                self.assertIn(partial_reason, result.stdout + result.stderr)
                if meta:
                    self.assertEqual(report['profile']['cache_hits'], 0, report)
        else:
            self.assertEqual(report['version'], '2.1.0', report)
            records = [row for run in report['runs'] for row in run.get('results', [])]
            observed = []
            for row in records:
                location = row['locations'][0]['physicalLocation']
                observed.append((row['ruleId'], location['region']['startLine'],
                                 location['region']['startColumn']))
                self.assertEqual(Path(location['artifactLocation']['uri']).name, target.name, row)
                self.assertEqual(row['level'], 'error', row)
            self.assertEqual(observed, expected, report)
            failed = [inv for run in report['runs'] for inv in run.get('invocations', [])
                      if inv.get('executionSuccessful') is False]
            self.assertEqual(bool(failed), partial, report)
            for invocation in failed:
                self.assertEqual(invocation['exitCode'], 2, invocation)
                self.assertIn(partial_reason, json.dumps(invocation))
        return report

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_copy_methods_public_json_and_sarif_preserve_identity_and_limits(self):
        alias = ('const items=[{html:"safe"},"safe"];\n'
                 'const reversed=items.toReversed();\n'
                 'const spliced=items.toSpliced(1,1);\n'
                 'const replaced=items.with(1,"new");\n'
                 'const sorted=spliced.toSorted();\n'
                 'reversed[1].html=req.query.html;\n'
                 'res.send(items[0].html);\nres.send(spliced[0].html);\n'
                 'res.send(replaced[0].html);\nres.send(sorted[0].html);\n')
        cases = (
            ('alias', alias, [('javascript.taint.xss', line, 1) for line in (7,8,9,10)], False),
            ('clean', 'const items=[req.query.html,"safe"];\n'
             'const a=items.toSpliced(0,1); const b=items.with(0,"safe");\n'
             'res.send(a[0]); res.send(b[0]); res.send(a.toReversed().toSorted()[0]);\n', [], False),
            ('comparator', 'const items=["b","a"]; const box={html:"safe"};\n'
             'items.toSorted((a,b)=>{box.html=req.query.html;return 0;});\n'
             'res.send(box.html);\n', [], True),
            ('coercion', 'const items=["safe",{toString(){return req.query.html;}}];\n'
             'items.toSorted();\nres.send(req.query.html);\n', [('javascript.taint.xss', 3, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-array-copy-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Array.toSorted')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_copy_methods_public_cache_invalidation_and_suppression(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-array-copy-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const items=[{html:"safe"}];\nconst copy=items.toReversed();\n'
                  'copy[0].html=req.query.html;\nres.send(items[0].html);\n')
        clean = unsafe.replace('copy[0].html=req.query.html;', 'copy[0]={html:req.query.html};')
        suppressed = unsafe.replace('res.send(items[0].html);', 'res.send(items[0].html); // ubs:ignore')
        for index, (source, expected) in enumerate((
                (unsafe, [('javascript.taint.xss', 4, 1)]),
                (unsafe, [('javascript.taint.xss', 4, 1)]),
                (clean, []), (suppressed, []), (unsafe, [('javascript.taint.xss', 4, 1)]))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                        expected=expected, cache=True)

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_sort_public_json_and_sarif_keep_findings_and_incomplete_status(self):
        cases = (
            ('alias', 'const items=["zz-clean",req.query.html]; const alias=items;\n'
             'alias.sort();\nres.send(items[0]);\n', [("javascript.taint.xss", 3, 1)], False),
            ('clean', 'const items=["b","a"];\nitems.sort();\nres.send(items[0]);\n', [], False),
            ('sanitized', 'const items=["zz-clean",DOMPurify.sanitize(req.query.html)];\n'
             'items.sort();\nres.send(items[0]);\n', [], False),
            ('comparator', 'const box={html:"safe"}; const items=["b","a"];\n'
             'items.sort((a,b)=>{box.html=req.query.html;return 0;});\nres.send(box.html);\n', [], True),
            ('coercion', 'const box={html:"safe"};\n'
             'const items=["b",{toString(){box.html=req.query.html;return "a";}}];\n'
             'items.sort();\nres.send(req.query.html);\n', [("javascript.taint.xss", 4, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-sort-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial)

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_sort_public_cache_invalidation_and_suppression(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-sort-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const items=["zz-clean",req.query.html];\nitems.sort();\n'
                  'res.send(items[0]);\n')
        clean = ('const items=["zz-clean",req.query.html];\nitems.sort(); items.fill("safe");\n'
                 'res.send(items[0]);\n')
        suppressed = unsafe.replace('res.send(items[0]);', 'res.send(items[0]); // ubs:ignore')
        for index, (source, expected) in enumerate((
                (unsafe, [("javascript.taint.xss", 3, 1)]),
                (unsafe, [("javascript.taint.xss", 3, 1)]),
                (clean, []), (suppressed, []), (unsafe, [("javascript.taint.xss", 3, 1)]))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                        expected=expected, cache=True)

    def test_spread_fill_bounds_follow_evaluated_argument_positions(self):
        calls = (
            'a.fill(...[], req.query.html, 1, 2)',
            'a.fill(...[req.query.html, ...[1, 2]])',
            'Array.prototype.fill.call(...[], a, req.query.html, 1, 2)',
            'Array.prototype.fill.call(...[a, req.query.html], 1, 2)',
            'const args=[a, req.query.html]; Array.prototype.fill.call(...args, 1, 2)',
            'const fill=a.fill; fill.call(...[a, ], req.query.html, 1, 2)',
            'const b=a; [].fill.call(...[b, req.query.html, -1], undefined)',
            'function put(items,v){items.fill(...[v,1,2]);} put(a,req.query.html)',
        )
        for call in calls:
            with self.subTest(call=call):
                source = ('const a=["first","last"];\n' + call
                          + ';\nres.send(a[0]);\nres.send(a[1]);')
                self.assert_runtime_sends(source, ['first', 'review-input'])
                self.assertEqual([f['line'] for f in self.scan(source, 'xss')], [4])

        for arguments, outputs, line in (
            ('...["clean", , 1]', ['clean', 'review-input'], 4),
            ('...["clean"], 1, 2', ['review-input', 'clean'], 3),
        ):
            with self.subTest(arguments=arguments):
                source = ('const a=[req.query.html,req.query.html];\n'
                          f'a.fill({arguments});\nres.send(a[0]);\nres.send(a[1]);')
                self.assert_runtime_sends(source, outputs)
                self.assertEqual([f['line'] for f in self.scan(source, 'xss')], [line])

    def test_spread_bounds_in_native_reads_and_copies(self):
        for expression in ('a.at(...[-1])', 'a.slice(...[1,2])[0]',
                           'a.splice(...[1,1])[0]', 'a.copyWithin(...[0,1,2])[0]'):
            with self.subTest(expression=expression):
                for first, second, expected, rules in (
                    ('"fixed"', 'req.query.html', 'review-input', ('xss',)),
                    ('req.query.html', '"fixed"', 'fixed', ()),
                ):
                    source = f'const a=[{first},{second}]; res.send({expression});'
                    self.assert_runtime_sends(source, [expected])
                    self.scan(source, *rules)

    def test_spread_bound_protocols_and_opaque_heap_scalars_remain_partial(self):
        for body, reason in (
            ('const args=[a,"clean"]; args[Symbol.iterator]=external; '
             'Array.prototype.fill.call(...args, 0, 1);', 'Array argument spread'),
            ('const fill=a.fill; Array.prototype[Symbol.iterator]=external; '
             'fill.call(...[a,"clean",0,1]);', 'Array argument spread'),
            ('Array.prototype[Symbol.iterator]=external; a.fill(...["clean",0,1]);', 'Array.fill'),
            ('const bounds=[0,1]; a.fill("clean", ...bounds);', 'Array.fill bound coercion'),
        ):
            with self.subTest(body=body):
                self.assert_fill_partial('const a=[req.query.html]; ' + body + ' res.send(a[0]);',
                                         'xss', reason=reason)

    def test_fill_mutates_alias_and_returns_same_array(self):
        self.scan('const items = ["safe"]; const alias = items; '
                  'const returned = alias.fill(req.query.html); '
                  'res.send(items[0]); res.send(returned[0]);', 'xss', 'xss')
        self.scan('const items = ["safe"]; res.send(items.fill(req.query.html).length);')

    def test_fill_literal_ranges_match_native_javascript(self):
        # Labels are predeclared from the ECMAScript fill contract, not scanner
        # output. Node checks the same examples independently when available.
        cases = [
            ('', (0, 1, 2)), (',1', (1, 2)), (',-2,-1', (1,)),
            (',1.9,2.8', (1,)), (',3,0', ()), (',0,0', ()),
            (',-99,99', (0, 1, 2)), (',null,undefined', (0, 1, 2)),
            (',false,true', (0,)), (',NaN,Infinity', (0, 1, 2)),
            (',1e309', ()), (',-1e309', (0, 1, 2)), (',0,NaN', ()),
            (',0,null', ()), (',0,-0.1', ()), (',(+1),(-1)', (1,)),
        ]
        for suffix, changed in cases:
            with self.subTest(suffix=suffix):
                source = ('const items = ["a", "b", "c"];\n'
                          f'items.fill(req.query.html{suffix});\n'
                          'res.send(items[0]);\nres.send(items[1]);\nres.send(items[2]);')
                findings = self.scan(source, *('xss' for _ in changed))
                self.assertEqual([finding['line'] for finding in findings], [3 + i for i in changed])
                self.assert_runtime_sends(source, [
                    'review-input' if i in changed else value for i, value in enumerate(('a', 'b', 'c'))])

    def test_fill_cleanup_only_replaces_selected_indices(self):
        self.scan('const items = [req.query.html, req.query.html, req.query.html]; '
                  'items.fill("safe", 1, 2); res.send(items[0]); res.send(items[1]); '
                  'res.send(items[2]);', 'xss', 'xss')
        self.scan('const items = [req.query.html]; items.fill("safe"); res.send(items[0]);')
        self.scan('const items = [req.query.html]; items.fill(); res.send(items[0]);')

    def test_fill_creates_holes_but_preserves_length_and_named_properties(self):
        self.scan('const items = [,,]; items.label = "safe"; '
                  'items.fill(req.query.html); res.send(items[0]); res.send(items[1]); '
                  'res.send(items.length); res.send(items.label); res.send(items[2]);', 'xss', 'xss')
        self.scan('const items = [req.query.html]; items["-1"] = req.query.html; '
                  'items.fill("safe"); res.send(items[0]); res.send(items["-1"]);', 'xss')
        self.scan('const items = []; items.fill(req.query.html); res.send(items[0]);')
        self.scan('const items = []; Object.freeze(items); items.fill(req.query.html); res.send(items[0]);')
        self.scan('const items = ["safe"]; Object.freeze(items); '
                  'items.fill(req.query.html, 1, 0); res.send(items[0]);')

    def test_fill_preserves_shared_object_value_identity(self):
        source = ('const value = {html: "safe"}; const items = [null, null]; '
                  'items.fill(value); items[0].html = req.query.html; res.send(items[1].html);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])

    def test_fill_captures_receiver_and_callee_before_evaluating_arguments(self):
        source = ('let items = ["old"]; const original = items; '
                  'function input() { items = ["new"]; return req.query.html; } '
                  'const returned = items.fill(input()); '
                  'res.send(original[0]); res.send(items[0]); res.send(returned[0]);')
        self.scan(source, 'xss', 'xss')
        self.assert_runtime_sends(source, ['review-input', 'new', 'review-input'])
        source = ('function foreign() {} const items = ["old"]; function input() { '
                  'items.fill = foreign; return req.query.html; } '
                  'items.fill(input()); res.send(items[0]);')
        self.scan(source, 'xss')
        self.scan('const items = ["old"]; function input() { '
                  'items.length = 2; return req.query.html; } '
                  'items.fill(input()); res.send(items[1]);', 'xss')

    def test_fill_summaries_reach_caller_and_keep_sanitizer_domains(self):
        self.scan('function fill(items, value) { return items.fill(value); } '
                  'const items = ["safe"]; const returned = fill(items, req.query.html); '
                  'res.send(items[0]); res.send(returned[0]);', 'xss', 'xss')
        self.scan('const items = ["safe"]; items.fill(DOMPurify.sanitize(req.query.html)); '
                  'res.send(items[0]); eval(items[0]);', 'eval')
        self.scan('const items = ["safe"]; items.fill(req.query.html); '
                  'res.send(items[0]); eval(items[0]); db.query(items[0]); shell.exec(items[0]);',
                  'xss', 'eval', 'sql', 'command')

    def test_fill_comma_arguments_preserve_receiver_and_last_value(self):
        source = ('let items = ["old"]; const original = items;\n'
                  'const returned = items.fill((items = ["new"], req.query.html));\n'
                  'res.send(original[0]);\nres.send(items[0]);\nres.send(returned[0]);')
        findings = self.scan(source, 'xss', 'xss')
        self.assertEqual([finding['line'] for finding in findings], [3, 5])
        self.assert_runtime_sends(source, ['review-input', 'new', 'review-input'])
        source = ('const items = [req.query.html];\n'
                  'items.fill((req.query.html, "safe"));\nres.send(items[0]);')
        self.scan(source)
        self.assert_runtime_sends(source, ['safe'])
        source = ('const items = ["old"]; const other = {html: "old"};\n'
                  'items.fill((other.html = req.query.html, "safe"));\n'
                  'res.send(items[0]);\nres.send(other.html);')
        findings = self.scan(source, 'xss')
        self.assertEqual([finding['line'] for finding in findings], [4])
        self.assert_runtime_sends(source, ['safe', 'review-input'])

    def test_fill_uncertain_receiver_and_branch_do_not_prove_cleanup(self):
        self.scan('const first = [req.query.html]; const second = [req.query.html]; '
                  'const items = flag ? first : second; items.fill("safe"); '
                  'res.send(first[0]); res.send(second[0]);', 'xss', 'xss')
        self.scan('const items = [req.query.html]; if (flag) items.fill("safe"); '
                  'res.send(items[0]);', 'xss')
        self.scan('const start = 1; const items = [req.query.html]; '
                  'items.fill("safe", start); res.send(items[0]);', 'xss')

    def test_fill_overrides_are_not_native_cleanup(self):
        for override in ('items.fill = external;', 'Array.prototype.fill = external;',
                         'items[method] = external;'):
            with self.subTest(override=override):
                self.scan('const items = [req.query.html]; ' + override
                          + 'items.fill("safe"); res.send(items[0]);', 'xss')

    def test_filter_preserves_captured_scalar_and_heap_writes(self):
        for predicate in ('true', 'false'):
            with self.subTest(predicate=predicate):
                source = ('let saved="safe"; const box={html:"safe"}; '
                          '[req.query.html].filter(value=>{saved=value;box.html=value;'
                          f'return {predicate};}});res.send(saved);res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input', 'review-input'])
                self.scan_sort(source, 'xss', 'xss')

    def test_filter_returns_original_values_instead_of_predicate_results(self):
        for predicate, expected, rules in (('true', 'review-input', ('xss',)),
                                            ('false', None, ()), ('null', None, ()),
                                            ('0', None, ()), ('"yes"', 'review-input', ('xss',))):
            with self.subTest(predicate=predicate):
                source = f'const out=[req.query.html].filter(value=>{predicate});res.send(out[0]);'
                self.assert_runtime_sends(source, [expected])
                self.scan_sort(source, *rules)
        source = 'const out=["safe"].filter(value=>req.query.html);res.send(out[0]);'
        self.assert_runtime_sends(source, ['safe'])
        self.scan_sort(source)

    def test_filter_compacts_holes_and_does_not_visit_empty_arrays(self):
        source = ('const out=[,"safe",,req.query.html,].filter(value=>true);'
                  'res.send(out[0]);res.send(out[1]);res.send(out[2]);res.send(out.length);')
        self.assert_runtime_sends(source, ['safe', 'review-input', None, 2])
        self.scan_sort(source, 'xss')
        for values in ('[]', '[,,,]'):
            with self.subTest(values=values):
                source = f'{values}.filter(value=>{{res.send(req.query.html);return true;}});'
                self.assert_runtime_sends(source, [])
                self.scan_sort(source)

    def test_filter_uses_fresh_array_and_preserves_shallow_element_aliases(self):
        source = ('const item={html:"safe"};const source=[item];'
                  'const out=source.filter(value=>true);out[0].html=req.query.html;'
                  'res.send(item.html);out[0]={html:"safe"};res.send(source[0].html);')
        self.assert_runtime_sends(source, ['review-input', 'review-input'])
        self.scan_sort(source, 'xss', 'xss')
        source = ('const source=[req.query.html];const out=source.filter(value=>true);'
                  'out[0]="safe";res.send(out[0]);res.send(source[0]);')
        self.assert_runtime_sends(source, ['safe', 'review-input'])
        self.scan_sort(source, 'xss')

    def test_filter_snapshots_selected_value_before_predicate_mutation(self):
        source = ('const items=[req.query.html];const out=items.filter(value=>{'
                  'items[0]="safe";return true;});res.send(out[0]);res.send(items[0]);')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        self.scan_sort(source, 'xss')
        source = ('const item={html:"safe"};const out=[item].filter(value=>{'
                  'value.html=req.query.html;return true;});res.send(out[0].html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')

    def test_filter_runs_all_predicates_and_preserves_ordered_replacement(self):
        for predicate in ('true', 'false'):
            for values, expected, rules in (('[req.query.html,"safe"]', 'safe', ()),
                                           ('["safe",req.query.html]', 'review-input', ('xss',))):
                with self.subTest(predicate=predicate, values=values):
                    source = ('let saved="safe";'
                              f'{values}.filter(value=>{{saved=value;return {predicate};}});res.send(saved);')
                    self.assert_runtime_sends(source, [expected])
                    self.scan_sort(source, *rules)

    def test_filter_reads_live_slots_under_snapshotted_length(self):
        for values, mutation, expected, rules in (
                ('["safe",req.query.html]', 'items[1]="safe";', ['safe', 'safe', None], ()),
                ('["safe",,]', 'items[1]=req.query.html;', ['safe', 'review-input', None], ('xss',)),
                ('["safe",req.query.html]', 'delete items[1];', ['safe', None, None], ()),
                ('["safe",req.query.html]', 'items.length=1;', ['safe', None, None], ()),
                ('["safe"]', 'items.push(req.query.html);', ['safe', None, None], ())):
            with self.subTest(values=values, mutation=mutation):
                source = (f'const items={values};const out=items.filter(value=>{{{mutation}return true;}});'
                          'res.send(out[0]);res.send(out[1]);res.send(out[2]);')
                self.assert_runtime_sends(source, expected)
                self.scan_sort(source, *rules)

    def test_filter_preserves_throws_and_prior_callback_effects(self):
        source = ('const box={html:"safe"};try{[req.query.html].filter(value=>{'
                  'box.html=value;throw value;});res.send(req.query.html);}'
                  'catch(error){res.send(error);}res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input', 'review-input'])
        self.scan_sort(source, 'xss', 'xss')
        source = ('const box={html:"safe"};try{[req.query.html].filter(value=>{'
                  'try{throw value;}finally{box.html=value;}});}catch(error){res.send(error);}'
                  'res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input', 'review-input'])
        self.scan_sort(source, 'xss', 'xss')

    def test_filter_binds_this_element_index_source_and_rest(self):
        source = ('const box={};const items=[{html:req.query.html}];'
                  'const out=items.filter(function({html},index,source){this.html=html;'
                  'res.send(index);res.send(source[0].html);return true;},box);'
                  'res.send(box.html);res.send(out[0].html);')
        self.assert_runtime_sends(source, [0, 'review-input', 'review-input', 'review-input'])
        self.scan_sort(source, 'xss', 'xss', 'xss')
        source = ('[req.query.html].filter((...args)=>{res.send(args[0]);res.send(args[1]);'
                  'res.send(args[2][0]);return true;});')
        self.assert_runtime_sends(source, ['review-input', 0, 'review-input'])
        self.scan_sort(source, 'xss', 'xss')

    def test_filter_keeps_unknown_selection_and_optional_slot_paths(self):
        source = ('const keep=true;const out=["safe",req.query.html].filter(value=>keep);'
                  'res.send(out[0]);res.send(out[1]);res.send(out.length);')
        self.assert_runtime_sends(source, ['safe', 'review-input', 2])
        self.scan_sort(source, 'xss', 'xss')  # either element may be the first accepted one
        source = ('const keep=true;const out=[req.query.html,"safe"].filter(value=>keep);'
                  'res.send(out[0]);res.send(out[1]);res.send(out[2]);'
                  'res.send(out.kind);res.send(out.length);')
        self.assert_runtime_sends(source, ['review-input', 'safe', None, None, 2])
        self.scan_sort(source, 'xss')  # the first input cannot move to a later output index
        source = ('const items=[,req.query.html];if(flag){items[0]="safe";}'
                  'const out=items.filter(value=>true);res.send(out[0]);res.send(out[1]);')
        self.assert_runtime_sends('const flag=false;' + source, ['review-input', None])
        self.assert_runtime_sends('const flag=true;' + source, ['safe', 'review-input'])
        self.scan_sort(source, 'xss', 'xss')
        source = ('const items=[,];if(flag){items[0]="safe";}let saved=req.query.html;'
                  'items.filter(value=>{saved="safe";return false;});res.send(saved);')
        self.assert_runtime_sends('const flag=false;' + source, ['review-input'])
        self.assert_runtime_sends('const flag=true;' + source, ['safe'])
        self.scan_sort(source, 'xss')

    def test_filter_helpers_preserve_captures_and_distinct_returned_arrays(self):
        source = ('const box={html:"safe"};const keep=value=>{box.html=value;return true;};'
                  'function run(items){return items.filter(keep);}'
                  'const dirty=run([req.query.html]);const clean=run(["safe"]);'
                  'res.send(dirty[0]);res.send(clean[0]);res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input', 'safe', 'safe'])
        self.scan_sort(source, 'xss')
        source = ('function choose(items,predicate){return items.filter(predicate);}'
                  'const out=choose([req.query.html],value=>true);res.send(out[0]);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')

    def test_filter_preserves_own_method_and_argument_evaluation_identity(self):
        source = ('const box={html:"safe"};const items=[req.query.html];'
                  'items.filter=function(callback){return ["safe"];};'
                  'const out=items.filter(value=>{box.html=value;return true;});'
                  'res.send(out[0]);res.send(box.html);')
        self.assert_runtime_sends(source, ['safe', 'safe'])
        self.scan_sort(source)
        source = ('const items=["safe"];items.filter=function(){return [req.query.html];};'
                  'const out=items.filter(value=>false);res.send(out[0]);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')
        source = ('const items=[req.query.html];function replace(){items.filter=function(){return [];};'
                  'return {};}const out=items.filter(value=>true,replace());res.send(out[0]);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')
        source = ('const items=[req.query.html];items.filter=function(){return [];};'
                  'delete items.filter;const out=items["filter"](value=>true);res.send(out[0]);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')

    def test_filter_keeps_unsupported_callbacks_species_and_protocols_explicit(self):
        for callback in ('external', 'async value=>value', 'function*(value){yield value;}'):
            with self.subTest(callback=callback):
                self.scan_sort('res.send(req.query.html);'
                               f'["safe"].filter({callback});', 'xss', partial='Array.filter.*synchronous callback')
        for mutation in ('items.constructor=foreign;', 'items[unknown]=external;',
                         'items.filter=external;', 'Array.prototype.filter=external;',
                         'Object.setPrototypeOf(items,foreign);'):
            with self.subTest(mutation=mutation):
                self.scan_sort('res.send(req.query.html);const items=["safe"];'
                               + mutation + 'items.filter(value=>true);', 'xss', partial='Array.filter|Own method')

    def test_filter_preserves_nested_chains_and_sparse_large_extents(self):
        source = ('const out=[,req.query.html].filter(value=>true).map(value=>({html:value}));'
                  'res.send(out[0].html);res.send([req.query.html].filter(value=>false)[0]);')
        self.assert_runtime_sends(source, ['review-input', None])
        self.scan_sort(source, 'xss')
        source = ('const items=[];items.length=4294967294;items[4294967293]=req.query.html;'
                  'const out=items.filter(value=>true);res.send(out[0]);res.send(out.length);')
        # Native filter would visit four billion indices; the sparse analyzer
        # must enumerate only present slots, under its normal work budget.
        self.scan_sort(source, 'xss')

    def test_filter_preserves_sink_specific_sanitization(self):
        source = ('const items=[DOMPurify.sanitize(req.query.html)];'
                  'const out=items.filter(value=>true);res.send(out[0]);'
                  'eval(out[0]);db.query(out[0]);shell.exec(out[0]);')
        findings = self.scan_sort(source, 'eval', 'sql', 'command')
        self.assertEqual(len(findings), 3)

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_filter_public_values_exceptions_and_incomplete_status(self):
        cases = (
            ('effects', 'let saved="safe";\nconst item={html:"safe"};\n'
             'const out=[item].filter(value=>true);\nout[0].html=req.query.html;\n'
             '[req.query.html].filter(value=>{saved=value;return false;});\n'
             'res.send(item.html);\nres.send(saved);\ntry{\n'
             '[req.query.html].filter(value=>{throw value;});\n}catch(error){\n'
             'res.send(error);\n}\n',
             [('javascript.taint.xss', line, 1) for line in (6, 7, 11)], False),
            ('clean', 'const out=[req.query.html].filter(value=>false);\nres.send(out[0]);\n'
             'let saved="safe";\n[req.query.html,"safe"].filter(value=>{saved=value;return true;});\n'
             'res.send(saved);\n[].filter(value=>{res.send(req.query.html);return true;});\n', [], False),
            ('partial', 'res.send(req.query.html);\nconst items=["safe"];\nitems.filter(external);\n',
             [('javascript.taint.xss', 1, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-filter-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            if name != 'partial':
                self.assert_runtime_sends(source, ['review-input'] * 3 if name == 'effects' else [None, 'safe'])
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Array.filter')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_filter_public_cache_invalidation_and_suppression(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-filter-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const items=[req.query.html];\nconst out=items.filter(value=>true);\n'
                  'res.send(out[0]);\n')
        clean = unsafe.replace('value=>true', 'value=>false')
        suppressed = unsafe.replace('res.send(out[0]);', 'res.send(out[0]); // ubs:ignore')
        for index, (source, expected) in enumerate((
                (unsafe, [('javascript.taint.xss', 3, 1)]),
                (unsafe, [('javascript.taint.xss', 3, 1)]),
                (clean, []), (suppressed, []), (unsafe, [('javascript.taint.xss', 3, 1)]))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                        expected=expected, cache=True)

    def test_find_preserves_captured_scalar_and_heap_writes(self):
        for method in ('find', 'findIndex'):
            with self.subTest(method=method):
                source = ('let saved="safe"; const box={html:"safe"}; '
                          f'[req.query.html].{method}(value=>{{saved=value;box.html=value;return false;}}); '
                          'res.send(saved);res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input', 'review-input'])
                self.scan_sort(source, 'xss', 'xss')

    def test_find_returns_original_match_and_clean_index(self):
        for predicate, matches in (('true', True), ('false', False), ('null', False),
                                   ('0', False), ('""', False), ('"yes"', True)):
            for method in ('find', 'findIndex'):
                with self.subTest(method=method, predicate=predicate):
                    source = f'res.send([req.query.html].{method}(value=>{predicate}));'
                    expected = ('review-input' if matches else None) if method == 'find' else (0 if matches else -1)
                    self.assert_runtime_sends(source, [expected])
                    self.scan_sort(source, *(('xss',) if matches and method == 'find' else ()))
        for method in ('find', 'findIndex'):
            source = f'res.send(["safe"].{method}(value=>req.query.html));'
            self.assert_runtime_sends(source, ['safe' if method == 'find' else 0])
            self.scan_sort(source)

    def test_find_short_circuits_and_orders_captured_writes(self):
        for method in ('find', 'findIndex'):
            for predicate in ('true', 'false'):
                for values, first_tainted in (('[req.query.html,"safe"]', True),
                                               ('["safe",req.query.html]', False)):
                    with self.subTest(method=method, predicate=predicate, values=values):
                        tainted = first_tainted if predicate == 'true' else not first_tainted
                        source = ('let saved="safe"; '
                                  f'{values}.{method}(value=>{{saved=value;return {predicate};}});res.send(saved);')
                        self.assert_runtime_sends(source, ['review-input' if tainted else 'safe'])
                        self.scan_sort(source, *(('xss',) if tainted else ()))

    def test_find_visits_holes_but_skips_empty_array_callbacks(self):
        for method in ('find', 'findIndex'):
            with self.subTest(method=method):
                source = f'[].{method}(()=>{{res.send(req.query.html);return true;}});res.send("safe");'
                self.assert_runtime_sends(source, ['safe'])
                self.scan_sort(source)
                source = ('let saved="safe"; '
                          f'[,].{method}(()=>{{saved=req.query.html;return false;}});res.send(saved);')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')
                source = ('let saved=req.query.html; '
                          f'[,req.query.html].{method}(value=>{{saved=value;return true;}});res.send(saved);')
                self.assert_runtime_sends(source, [None])
                self.scan_sort(source)
                source = ('let saved=req.query.html; '
                          f'["safe",,].{method}(value=>{{saved=value;return false;}});res.send(saved);')
                self.assert_runtime_sends(source, [None])
                self.scan_sort(source)

    def test_find_reads_live_slots_including_deleted_indices_with_snapshot_length(self):
        for method in ('find', 'findIndex'):
            for values, mutation, expected, rules in (
                    ('[req.query.html,"safe"]', 'items.length=0;', None, ()),
                    ('[req.query.html,"safe"]', 'delete items[1];', None, ()),
                    ('["safe",,]', 'items[1]=req.query.html;', 'review-input', ('xss',)),
                    ('[req.query.html]', 'items.push("safe");', 'review-input', ('xss',))):
                with self.subTest(method=method, values=values, mutation=mutation):
                    source = (f'const items={values};let saved="safe"; '
                              f'items.{method}(value=>{{saved=value;{mutation}return false;}});res.send(saved);')
                    self.assert_runtime_sends(source, [expected])
                    self.scan_sort(source, *rules)

    def test_find_keeps_pre_callback_match_and_shallow_identity(self):
        source = ('const items=[req.query.html]; '
                  'const selected=items.find(value=>{items[0]="safe";return true;}); '
                  'res.send(selected);res.send(items[0]);')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        self.scan_sort(source, 'xss')
        source = ('const box={html:"safe"};const items=[box]; '
                  'const selected=items.find(value=>true);selected.html=req.query.html;res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')

    def test_find_optional_holes_still_execute_callback(self):
        for method in ('find', 'findIndex'):
            with self.subTest(method=method):
                source = ('const items=[,req.query.html];if(flag){items[0]="safe";} '
                          'let saved=req.query.html; '
                          f'items.{method}(value=>{{saved="safe";return true;}});res.send(saved);')
                for flag in ('true', 'false'):
                    self.assert_runtime_sends(f'const flag={flag};' + source, ['safe'])
                self.scan_sort(source)

    def test_find_binds_callback_arguments_this_and_rest(self):
        for method in ('find', 'findIndex'):
            with self.subTest(method=method):
                source = ('const box={};const items=[{html:req.query.html}]; '
                          f'items.{method}(function({{html}},index,source){{this.html=html;'
                          'res.send(index);res.send(source[0].html);return true;},box);res.send(box.html);')
                self.assert_runtime_sends(source, [0, 'review-input', 'review-input'])
                self.scan_sort(source, 'xss', 'xss')
                source = (f'[req.query.html].{method}((...args)=>{{res.send(args[0]);'
                          'res.send(args[1]);res.send(args[2][0]);return true;});')
                self.assert_runtime_sends(source, ['review-input', 0, 'review-input'])
                self.scan_sort(source, 'xss', 'xss')

    def test_find_preserves_throws_effects_and_unknown_stop_states(self):
        for method in ('find', 'findIndex'):
            with self.subTest(method=method):
                source = ('const box={html:"safe"};try{'
                          f'[req.query.html].{method}(value=>{{box.html=value;throw value;}});'
                          'res.send(req.query.html);}catch(error){res.send(error);}res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input', 'review-input'])
                self.scan_sort(source, 'xss', 'xss')
                source = ('const stop=true;let saved="safe";'
                          f'[req.query.html,"safe"].{method}(value=>{{saved=value;return stop;}});res.send(saved);')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')

    def test_find_transports_callback_aliases_parameters_and_lexical_captures(self):
        for method in ('find', 'findIndex'):
            with self.subTest(method=method):
                source = ('const box={html:"safe"};const visit=value=>{box.html=value;return true;}; '
                          'const alias=visit; '
                          f'function run(items,predicate){{const box={{html:"local"}};return items.{method}(predicate);}} '
                          'run([req.query.html],alias);res.send(box.html);run(["safe"],alias);res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input', 'safe'])
                self.scan_sort(source, 'xss')
                self.scan_sort(f'let saved;[].{method}(saved=()=>{{res.send(req.query.html);}});saved();', 'xss')

    def test_find_respects_own_methods_and_argument_evaluation_order(self):
        for method in ('find', 'findIndex'):
            with self.subTest(method=method):
                source = ('const box={html:"safe"};const items=[req.query.html];'
                          f'items.{method}=function(callback){{return "safe";}};'
                          f'res.send(items.{method}(value=>{{box.html=value;}}));res.send(box.html);')
                self.assert_runtime_sends(source, ['safe', 'safe'])
                self.scan_sort(source)
                source = ('const items=["safe"];'
                          f'items.{method}=function(){{return req.query.html;}};res.send(items.{method}(()=>true));')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')
                source = ('const box={html:req.query.html};const items=["safe"];'
                          f'function replace(){{items.{method}=function(){{box.html=req.query.html;}};return {{}};}}'
                          f'items.{method}(value=>{{box.html=value;return true;}},replace());res.send(box.html);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan_sort(source)

    def test_find_rejects_unknown_callbacks_protocols_and_unbounded_hole_walks(self):
        for method in ('find', 'findIndex'):
            for callback in ('external', 'async value=>value', 'function*(value){yield value;}'):
                with self.subTest(method=method, callback=callback):
                    self.scan_sort('res.send(req.query.html);'
                                   f'["safe"].{method}({callback});', 'xss',
                                   partial=f'Array.{method}.*synchronous callback')
            for change in ('items[unknown]=external;', f'items.{method}=external;',
                           f'Array.prototype.{method}=external;', 'Object.setPrototypeOf(items,foreign);'):
                with self.subTest(method=method, change=change):
                    self.scan_sort('res.send(req.query.html);const items=["safe"];'
                                   + change + f'items.{method}(value=>true);', 'xss',
                                   partial=f'Array.{method}|Own method')
            with self.subTest(method=method, extent='unknown'):
                self.scan_sort('res.send(req.query.html);const items=[...unknown];'
                               f'items.{method}(value=>true);', 'xss', partial=f'Array.{method}.*finite')
            with self.subTest(method=method, extent='large'):
                source = ('const items=[];items.length=4294967294;'
                          f'items.{method}(()=>{{res.send(req.query.html);return true;}});')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')
                self.scan_sort('res.send(req.query.html);const items=[];items.length=4294967294;'
                               f'items.{method}(()=>false);', 'xss', partial='work limit')
                self.scan_sort('res.send(req.query.html);const stop=true;'
                               'const items=[];items.length=4294967294;'
                               f'items.{method}(()=>stop);', 'xss', partial='work limit')
                source = ('const items=[];items.length=4294967294;try{'
                          f'items.{method}(()=>{{throw req.query.html;}});'
                          '}catch(error){res.send(error);}')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')

    def test_find_keeps_optional_callback_defaults_explicit(self):
        for method in ('find', 'findIndex'):
            with self.subTest(method=method):
                source = ('const items=[,];if(flag){items[0]={};}let saved="safe";'
                          f'items.{method}((value=(saved=req.query.html))=>false);res.send(saved);')
                self.assert_runtime_sends('const flag=false;' + source, ['review-input'])
                self.assert_runtime_sends('const flag=true;' + source, ['safe'])
                self.scan_sort(source, 'xss', partial=f'Array.{method} element default')

    def test_find_definite_holes_throw_on_destructuring_and_run_defaults(self):
        for method in ('find', 'findIndex'):
            for pattern in ('{html}', '[html]'):
                with self.subTest(method=method, pattern=pattern):
                    source = ('let saved=req.query.html;try{'
                              f'[,].{method}(({pattern})=>{{saved="safe";res.send(req.query.html);return true;}});'
                              '}catch(error){res.send("caught");}res.send(saved);')
                    self.assert_runtime_sends(source, ['caught', 'review-input'])
                    self.scan_sort(source, 'xss')
            with self.subTest(method=method, defaults=True):
                source = ('let saved=req.query.html;'
                          f'[,].{method}((value=(saved="safe"))=>true);res.send(saved);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan_sort(source)

    def test_find_transports_selected_callables_without_erasing_no_match(self):
        source = ('function visit(value){res.send(value);}'
                  'const callback=[visit].find(()=>true);[req.query.html].forEach(callback);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')
        source = ('const stop=true;function visit(value){res.send(value);}'
                  'const callback=[visit].find(()=>stop);res.send(req.query.html);'
                  '[req.query.html].forEach(callback);')
        self.assert_runtime_sends(source, ['review-input', 'review-input'])
        self.scan_sort(source, 'xss', partial='Array.forEach.*synchronous callback')

    def test_find_preserves_nested_chains_and_sink_specific_sanitizers(self):
        source = ('const selected=[req.query.html].map(value=>({html:value})).find(value=>true);'
                  'res.send(selected.html);res.send([[req.query.html]].find(value=>true).find(value=>true));')
        self.assert_runtime_sends(source, ['review-input', 'review-input'])
        self.scan_sort(source, 'xss', 'xss')
        source = ('const out=[DOMPurify.sanitize(req.query.html)].find(value=>true);'
                  'res.send(out);eval(out);db.query(out);shell.exec(out);')
        self.scan_sort(source, 'eval', 'sql', 'command')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_find_public_matches_callback_effects_and_incomplete_status(self):
        cases = (
            ('effects', 'let saved="safe";\nconst item={html:"safe"};\n'
             'const selected=[item].find(value=>true);\nselected.html=req.query.html;\n'
             '[req.query.html].findIndex(value=>{saved=value;return false;});\n'
             'res.send(item.html);\nres.send(saved);\ntry{\n'
             '[req.query.html].find(value=>{throw value;});\n}catch(error){\n'
             'res.send(error);\n}\n',
             [('javascript.taint.xss', line, 1) for line in (6, 7, 11)], False),
            ('clean', 'res.send([req.query.html].find(value=>false));\n'
             'res.send([req.query.html].findIndex(value=>true));\nlet saved=req.query.html;\n'
             '["safe",req.query.html].find(value=>{saved=value;return true;});\n'
             'res.send(saved);\n[].findIndex(()=>{res.send(req.query.html);return true;});\n', [], False),
            ('partial', 'res.send(req.query.html);\nconst items=["safe"];\nitems.findIndex(external);\n',
             [('javascript.taint.xss', 1, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-find-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            if not partial:
                self.assert_runtime_sends(source, ['review-input'] * 3 if name == 'effects' else [None, 0, 'safe'])
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Array.findIndex')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_find_public_cache_invalidation_and_suppression(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-find-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const items=[req.query.html];\nconst selected=items.find(value=>true);\n'
                  'res.send(selected);\n')
        clean = unsafe.replace('value=>true', 'value=>false')
        suppressed = unsafe.replace('res.send(selected);', 'res.send(selected); // ubs:ignore')
        for index, (source, expected) in enumerate((
                (unsafe, [('javascript.taint.xss', 3, 1)]),
                (unsafe, [('javascript.taint.xss', 3, 1)]),
                (clean, []), (suppressed, []), (unsafe, [('javascript.taint.xss', 3, 1)]))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                        expected=expected, cache=True)

    def test_find_last_orders_captured_writes_and_stops_from_the_right(self):
        for method in ('findLast', 'findLastIndex'):
            for predicate in ('true', 'false'):
                for values, last_tainted in (('["safe",req.query.html]', True),
                                              ('[req.query.html,"safe"]', False)):
                    with self.subTest(method=method, predicate=predicate, values=values):
                        tainted = last_tainted if predicate == 'true' else not last_tainted
                        source = ('let saved="safe";const box={html:"safe"};'
                                  f'{values}.{method}(value=>{{saved=value;box.html=value;return {predicate};}});'
                                  'res.send(saved);res.send(box.html);')
                        self.assert_runtime_sends(source, ['review-input' if tainted else 'safe'] * 2)
                        self.scan_sort(source, *(('xss', 'xss') if tainted else ()))

    def test_find_last_selects_original_values_and_returns_clean_indices(self):
        for predicate, matched in (('true', True), ('false', False), ('null', False),
                                   ('0', False), ('""', False), ('"yes"', True)):
            for method in ('findLast', 'findLastIndex'):
                with self.subTest(method=method, predicate=predicate):
                    source = f'res.send(["safe",req.query.html].{method}(value=>{predicate}));'
                    expected = ('review-input' if matched else None) if method == 'findLast' else (1 if matched else -1)
                    self.assert_runtime_sends(source, [expected])
                    self.scan_sort(source, *(('xss',) if matched and method == 'findLast' else ()))
        for method in ('findLast', 'findLastIndex'):
            source = f'res.send(["safe"].{method}(value=>req.query.html));'
            self.assert_runtime_sends(source, ['safe' if method == 'findLast' else 0])
            self.scan_sort(source)

    def test_find_last_visits_trailing_holes_and_skips_empty_array_callbacks(self):
        for method in ('findLast', 'findLastIndex'):
            with self.subTest(method=method):
                source = f'[].{method}(()=>{{res.send(req.query.html);return true;}});res.send("safe");'
                self.assert_runtime_sends(source, ['safe'])
                self.scan_sort(source)
                source = ('let saved="safe";'
                          f'[,].{method}(()=>{{saved=req.query.html;return true;}});res.send(saved);')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')
                source = ('let saved=req.query.html;'
                          f'[req.query.html,,].{method}(value=>{{saved=value;return true;}});res.send(saved);')
                self.assert_runtime_sends(source, [None])
                self.scan_sort(source)

    def test_find_last_reads_live_lower_slots_with_snapshot_length(self):
        for method in ('findLast', 'findLastIndex'):
            for values, mutation, expected, rules in (
                    ('["safe",req.query.html]', 'items.length=0;', None, ()),
                    ('["safe",req.query.html]', 'delete items[0];', None, ()),
                    ('[,"safe"]', 'items[0]=req.query.html;', 'review-input', ('xss',)),
                    ('[req.query.html]', 'items.push("safe");', 'review-input', ('xss',)),
                    ('["safe",req.query.html]', 'items.unshift(req.query.html);', 'review-input', ('xss',))):
                with self.subTest(method=method, values=values, mutation=mutation):
                    source = (f'const items={values};let saved="safe";'
                              f'items.{method}(value=>{{saved=value;{mutation}return false;}});res.send(saved);')
                    self.assert_runtime_sends(source, [expected])
                    self.scan_sort(source, *rules)

    def test_find_last_preserves_pre_callback_value_and_shallow_identity(self):
        source = ('const items=["safe",req.query.html];'
                  'const selected=items.findLast(value=>{items[1]="safe";return true;});'
                  'res.send(selected);res.send(items[1]);')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        self.scan_sort(source, 'xss')
        source = ('const box={html:"safe"};const items=[{},box];'
                  'const selected=items.findLast(value=>true);selected.html=req.query.html;'
                  'res.send(box.html);res.send(items[0].html);')
        self.assert_runtime_sends(source, ['review-input', None])
        self.scan_sort(source, 'xss')

    def test_find_last_optional_slots_and_definite_hole_defaults(self):
        for method in ('findLast', 'findLastIndex'):
            with self.subTest(method=method):
                source = ('const items=[req.query.html,,];if(flag){items[1]="safe";}'
                          'let saved=req.query.html;'
                          f'items.{method}(value=>{{saved="safe";return true;}});res.send(saved);')
                for flag in ('false', 'true'):
                    self.assert_runtime_sends(f'const flag={flag};' + source, ['safe'])
                self.scan_sort(source)
                source = ('let saved=req.query.html;'
                          f'[,].{method}((value=(saved="safe"))=>true);res.send(saved);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan_sort(source)
                source = ('const items=[,];if(flag){items[0]={};}let saved="safe";'
                          f'items.{method}((value=(saved=req.query.html))=>false);res.send(saved);')
                self.assert_runtime_sends('const flag=false;' + source, ['review-input'])
                self.assert_runtime_sends('const flag=true;' + source, ['safe'])
                self.scan_sort(source, 'xss', partial=f'Array.{method} element default')

    def test_find_last_hole_destructuring_preserves_abrupt_completion(self):
        for method in ('findLast', 'findLastIndex'):
            for pattern in ('{html}', '[html]'):
                with self.subTest(method=method, pattern=pattern):
                    source = ('let saved=req.query.html;try{'
                              f'[,].{method}(({pattern})=>{{saved="safe";res.send(req.query.html);return true;}});'
                              '}catch(error){res.send("caught");}res.send(saved);')
                    self.assert_runtime_sends(source, ['caught', 'review-input'])
                    self.scan_sort(source, 'xss')

    def test_find_last_binds_this_source_rest_and_clean_index(self):
        for method in ('findLast', 'findLastIndex'):
            with self.subTest(method=method):
                source = ('const box={};const items=[{}, {html:req.query.html}];'
                          f'items.{method}(function({{html}},index,source){{this.html=html;'
                          'res.send(index);res.send(source[1].html);return true;},box);res.send(box.html);')
                self.assert_runtime_sends(source, [1, 'review-input', 'review-input'])
                self.scan_sort(source, 'xss', 'xss')
                source = (f'["safe",req.query.html].{method}((...args)=>{{res.send(args[0]);'
                          'res.send(args[1]);res.send(args[2][1]);return true;});')
                self.assert_runtime_sends(source, ['review-input', 1, 'review-input'])
                self.scan_sort(source, 'xss', 'xss')

    def test_find_last_keeps_throws_effects_and_unknown_stopped_paths(self):
        for method in ('findLast', 'findLastIndex'):
            with self.subTest(method=method):
                source = ('const box={html:"safe"};try{'
                          f'["safe",req.query.html].{method}(value=>{{box.html=value;throw value;}});'
                          'res.send(req.query.html);}catch(error){res.send(error);}res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input', 'review-input'])
                self.scan_sort(source, 'xss', 'xss')
                source = ('const stop=true;let saved="safe";'
                          f'["safe",req.query.html].{method}(value=>{{saved=value;return stop;}});res.send(saved);')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')

    def test_find_last_keeps_lexical_captures_and_selected_callable_alternatives(self):
        for method in ('findLast', 'findLastIndex'):
            with self.subTest(method=method):
                source = ('const box={html:"safe"};const visit=value=>{box.html=value;return true;};'
                          'const alias=visit;'
                          f'function run(items,predicate){{const box={{html:"local"}};return items.{method}(predicate);}}'
                          'run(["safe",req.query.html],alias);res.send(box.html);'
                          'run([req.query.html,"safe"],alias);res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input', 'safe'])
                self.scan_sort(source, 'xss')
        source = ('function visit(value){res.send(value);}'
                  'const callback=[visit].findLast(()=>true);[req.query.html].forEach(callback);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan_sort(source, 'xss')
        source = ('const stop=true;function visit(value){res.send(value);}'
                  'const callback=[visit].findLast(()=>stop);res.send(req.query.html);'
                  '[req.query.html].forEach(callback);')
        self.assert_runtime_sends(source, ['review-input', 'review-input'])
        self.scan_sort(source, 'xss', partial='Array.forEach.*synchronous callback')

    def test_find_last_respects_own_methods_and_evaluation_order(self):
        for method in ('findLast', 'findLastIndex'):
            with self.subTest(method=method):
                source = ('const box={html:"safe"};const items=[req.query.html];'
                          f'items.{method}=function(callback){{return "safe";}};'
                          f'res.send(items.{method}(value=>{{box.html=value;}}));res.send(box.html);')
                self.assert_runtime_sends(source, ['safe', 'safe'])
                self.scan_sort(source)
                source = ('const items=["safe"];'
                          f'items.{method}=function(){{return req.query.html;}};res.send(items.{method}(()=>true));')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')
                source = ('const box={html:req.query.html};const items=["safe"];'
                          f'function replace(){{items.{method}=function(){{box.html=req.query.html;}};return {{}};}}'
                          f'items.{method}(value=>{{box.html=value;return true;}},replace());res.send(box.html);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan_sort(source)

    def test_find_last_composes_computed_methods_chains_and_sanitizer_domains(self):
        source = ('const values=["safe",req.query.html];'
                  'res.send(values["findLast"](value=>true));'
                  'res.send(values["findLastIndex"](value=>true));'
                  'res.send([["safe"],[req.query.html]].findLast(value=>true).find(value=>true));'
                  'res.send([req.query.html].map(value=>({html:value})).findLast(value=>true).html);')
        self.assert_runtime_sends(source, ['review-input', 1, 'review-input', 'review-input'])
        self.scan_sort(source, 'xss', 'xss', 'xss')
        source = ('const out=[DOMPurify.sanitize(req.query.html)].findLast(value=>true);'
                  'res.send(out);eval(out);db.query(out);shell.exec(out);')
        self.scan_sort(source, 'eval', 'sql', 'command')

    def test_find_last_keeps_unknown_callbacks_and_protocols_explicit(self):
        for method in ('findLast', 'findLastIndex'):
            for callback in ('external', 'async value=>value', 'function*(value){yield value;}'):
                with self.subTest(method=method, callback=callback):
                    self.scan_sort('res.send(req.query.html);'
                                   f'["safe"].{method}({callback});', 'xss',
                                   partial=f'Array.{method}.*synchronous callback')
            for change in ('items[unknown]=external;', f'items.{method}=external;',
                           f'Array.prototype.{method}=external;', 'Object.setPrototypeOf(items,foreign);'):
                with self.subTest(method=method, change=change):
                    self.scan_sort('res.send(req.query.html);const items=["safe"];'
                                   + change + f'items.{method}(value=>true);', 'xss',
                                   partial=f'Array.{method}|Own method')
            with self.subTest(method=method, extent='unknown'):
                self.scan_sort('res.send(req.query.html);const items=[...unknown];'
                               f'items.{method}(value=>true);', 'xss', partial=f'Array.{method}.*finite')

    def test_find_last_bounds_reverse_sparse_work_after_first_stop_or_throw(self):
        for method in ('findLast', 'findLastIndex'):
            with self.subTest(method=method):
                source = ('const items=[];items.length=4294967294;'
                          f'items.{method}(()=>{{res.send(req.query.html);return true;}});')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')
                self.scan_sort('res.send(req.query.html);const items=[];items.length=4294967294;'
                               f'items.{method}(()=>false);', 'xss', partial='work limit')
                self.scan_sort('res.send(req.query.html);const stop=true;'
                               'const items=[];items.length=4294967294;'
                               f'items.{method}(()=>stop);', 'xss', partial='work limit')
                source = ('const items=[];items.length=4294967294;try{'
                          f'items.{method}(()=>{{throw req.query.html;}});'
                          '}catch(error){res.send(error);}')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_find_last_public_results_effects_and_partial_status(self):
        cases = (
            ('effects', 'let saved="safe";\nconst item={html:"safe"};\n'
             'const selected=[{},item].findLast(value=>true);\nselected.html=req.query.html;\n'
             '["safe",req.query.html].findLastIndex(value=>{saved=value;return true;});\n'
             'res.send(item.html);\nres.send(saved);\ntry{\n'
             '["safe",req.query.html].findLast(value=>{throw value;});\n}catch(error){\n'
             'res.send(error);\n}\n',
             [('javascript.taint.xss', line, 1) for line in (6, 7, 11)], False),
            ('clean', 'res.send([req.query.html].findLast(value=>false));\n'
             'res.send([req.query.html].findLastIndex(value=>true));\nlet saved=req.query.html;\n'
             '[req.query.html,"safe"].findLast(value=>{saved=value;return true;});\n'
             'res.send(saved);\n[].findLastIndex(()=>{res.send(req.query.html);return true;});\n', [], False),
            ('partial', 'res.send(req.query.html);\nconst items=["safe"];\nitems.findLastIndex(external);\n',
             [('javascript.taint.xss', 1, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-find-last-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            if not partial:
                self.assert_runtime_sends(source, ['review-input'] * 3 if name == 'effects' else [None, 0, 'safe'])
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Array.findLastIndex')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_find_last_public_cache_invalidation_and_suppression(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-find-last-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const items=["safe",req.query.html];\nconst selected=items.findLast(value=>true);\n'
                  'res.send(selected);\n')
        clean = unsafe.replace('value=>true', 'value=>false')
        suppressed = unsafe.replace('res.send(selected);', 'res.send(selected); // ubs:ignore')
        for index, (source, expected) in enumerate((
                (unsafe, [('javascript.taint.xss', 3, 1)]),
                (unsafe, [('javascript.taint.xss', 3, 1)]),
                (clean, []), (suppressed, []), (unsafe, [('javascript.taint.xss', 3, 1)]))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                report = self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                                expected=expected, cache=True)
                self.assertEqual(report['profile']['cache_hits'], 1 if index in (1, 4) else 0, report)

    def test_predicates_preserve_captured_scalar_and_heap_writes(self):
        for method, result in (('some', 'false'), ('every', 'true')):
            with self.subTest(method=method):
                source = ('let saved = "safe"; const box = {html:"safe"}; '
                          f'[req.query.html].{method}(value => {{ saved = value; box.html = value; '
                          f'return {result}; }}); res.send(saved); res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input', 'review-input'])
                self.scan_sort(source, 'xss', 'xss')

    def test_predicates_return_clean_booleans(self):
        for method in ('some', 'every'):
            with self.subTest(method=method):
                source = f'res.send([req.query.html].{method}(value => value));'
                self.assert_runtime_sends(source, [True])
                self.scan_sort(source)

    def test_predicates_continue_in_order_and_replace_prior_writes(self):
        for method, result in (('some', 'false'), ('every', 'true')):
            for values, expected, rules in (
                    ('[req.query.html,"safe"]', 'safe', ()),
                    ('["safe",req.query.html]', 'review-input', ('xss',))):
                with self.subTest(method=method, values=values):
                    source = ('let saved = "safe"; '
                              f'{values}.{method}(value => {{ saved = value; return {result}; }}); '
                              'res.send(saved);')
                    self.assert_runtime_sends(source, [expected])
                    self.scan_sort(source, *rules)

    def test_predicates_stop_before_later_writes_or_cleanup(self):
        for method, result in (('some', 'true'), ('every', 'false')):
            for values, expected, rules in (
                    ('["safe",req.query.html]', 'safe', ()),
                    ('[req.query.html,"safe"]', 'review-input', ('xss',))):
                with self.subTest(method=method, values=values):
                    source = ('const box = {html:"safe"}; '
                              f'{values}.{method}(value => {{ box.html = value; return {result}; }}); '
                              'res.send(box.html);')
                    self.assert_runtime_sends(source, [expected])
                    self.scan_sort(source, *rules)

    def test_predicates_apply_boolean_conversion_to_literal_returns(self):
        for returned, truth in (('true', True), ('false', False), ('null', False),
                                ('0', False), ('-0', False), ('0n', False), ('1', True),
                                ('""', False), ('"yes"', True), ('[]', True), ('{}', True)):
            for method in ('some', 'every'):
                with self.subTest(method=method, returned=returned):
                    stopping = truth == (method == 'some')
                    source = ('let saved = "safe"; '
                              f'["safe",req.query.html].{method}(value => {{ '
                              f'saved = value; return {returned}; }}); res.send(saved);')
                    self.assert_runtime_sends(source, ['safe' if stopping else 'review-input'])
                    self.scan_sort(source, *(() if stopping else ('xss',)))

    def test_predicates_implicit_return_is_false_and_unreachable_returns_do_not_count(self):
        for method, expected, rules in (('some', 'review-input', ('xss',)), ('every', 'safe', ())):
            with self.subTest(method=method):
                source = ('let saved = "safe"; '
                          f'["safe",req.query.html].{method}(value => {{ saved = value; }}); res.send(saved);')
                self.assert_runtime_sends(source, [expected])
                self.scan_sort(source, *rules)
        for method, result in (('some', 'true'), ('every', 'false')):
            with self.subTest(method=method, unreachable=True):
                source = ('let saved = "safe"; '
                          f'["safe",req.query.html].{method}(value => {{ saved = value; '
                          f'if (true) {{ return {result}; }} return !{result}; }}); res.send(saved);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan_sort(source)

    def test_predicates_skip_holes_empty_arrays_and_unexecuted_callback_sinks(self):
        for method in ('some', 'every'):
            for values in ('[]', '[,,,]'):
                with self.subTest(method=method, values=values):
                    source = (f'{values}.{method}(value => {{ res.send(req.query.html); return true; }}); '
                              'res.send("safe");')
                    self.assert_runtime_sends(source, ['safe'])
                    self.scan_sort(source)
            source = (f'[,req.query.html].{method}(value => {{ res.send(value); return true; }});')
            self.assert_runtime_sends(source, ['review-input'])
            self.scan_sort(source, 'xss')

    def test_predicates_read_live_slots_and_snapshot_length(self):
        for method, result in (('some', 'false'), ('every', 'true')):
            for values, mutation, expected, rules in (
                    ('["safe",req.query.html]', 'items[1] = "safe";', 'safe', ()),
                    ('["safe","safe"]', 'items[1] = req.query.html;', 'review-input', ('xss',)),
                    ('["safe",,]', 'items[1] = req.query.html;', 'review-input', ('xss',)),
                    ('["safe",req.query.html]', 'items.length = 1;', 'safe', ()),
                    ('["safe",req.query.html]', 'delete items[1];', 'safe', ()),
                    ('["safe"]', 'items.push(req.query.html);', 'safe', ())):
                with self.subTest(method=method, values=values, mutation=mutation):
                    source = (f'const items = {values}; let saved = "safe"; '
                              f'items.{method}(value => {{ saved = value; {mutation} return {result}; }}); '
                              'res.send(saved);')
                    self.assert_runtime_sends(source, [expected])
                    self.scan_sort(source, *rules)

    def test_predicates_bind_element_index_source_this_and_rest_parameters(self):
        for method, result in (('some', 'false'), ('every', 'true')):
            with self.subTest(method=method):
                source = ('const box = {}; const items = [{html:req.query.html}]; '
                          f'items.{method}(function({{html}}, index, source) {{ this.html = html; '
                          f'res.send(index); res.send(source[0].html); return {result}; }}, box); '
                          'res.send(box.html);')
                self.assert_runtime_sends(source, [0, 'review-input', 'review-input'])
                self.scan_sort(source, 'xss', 'xss')
                source = (f'[req.query.html].{method}((...args) => {{ res.send(args[0]); '
                          f'res.send(args[1]); res.send(args[2][0]); return {result}; }});')
                self.assert_runtime_sends(source, ['review-input', 0, 'review-input'])
                self.scan_sort(source, 'xss', 'xss')

    def test_predicates_preserve_callback_throws_and_prior_effects(self):
        for method in ('some', 'every'):
            with self.subTest(method=method):
                source = ('const box = {html:"safe"}; try { '
                          f'[req.query.html].{method}(value => {{ box.html = value; throw value; }}); '
                          'res.send(req.query.html); } catch (error) { res.send(error); } res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input', 'review-input'])
                self.scan_sort(source, 'xss', 'xss')

    def test_predicates_keep_unknown_stop_and_continue_states_separate(self):
        for method, result in (('some', 'true'), ('every', 'false')):
            with self.subTest(method=method):
                source = (f'const stop = {result}; let saved = "safe"; '
                          f'[req.query.html,"safe"].{method}(value => {{ saved = value; return stop; }}); '
                          'res.send(saved);')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')
                source = (f'const stop = {result}; let saved = req.query.html; '
                          f'["safe","safe"].{method}(value => {{ saved = value; return stop; }}); '
                          'res.send(saved);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan_sort(source)

    def test_predicates_optional_slots_preserve_skipped_callback_paths(self):
        for method, result in (('some', 'true'), ('every', 'false')):
            with self.subTest(method=method):
                source = ('const items = [,req.query.html]; if (flag) { items[0] = "safe"; } '
                          'let saved = "safe"; '
                          f'items.{method}(value => {{ saved = value; return {result}; }}); res.send(saved);')
                self.assert_runtime_sends('const flag = false; ' + source, ['review-input'])
                self.assert_runtime_sends('const flag = true; ' + source, ['safe'])
                self.scan_sort(source, 'xss')
                source = ('const items = [,]; if (flag) { items[0] = "safe"; } '
                          'let saved = req.query.html; '
                          f'items.{method}(value => {{ saved = "safe"; return {result}; }}); res.send(saved);')
                self.assert_runtime_sends('const flag = false; ' + source, ['review-input'])
                self.assert_runtime_sends('const flag = true; ' + source, ['safe'])
                self.scan_sort(source, 'xss')

    def test_predicates_resolve_named_callbacks_helpers_and_nested_visits(self):
        for method, result in (('some', 'false'), ('every', 'true')):
            with self.subTest(method=method):
                source = ('const box = {html:"safe"}; '
                          f'function visit(value) {{ box.html = value; return {result}; }} '
                          f'function run(items) {{ return items.{method}(visit); }} '
                          'run([req.query.html]); res.send(box.html); run(["safe"]); res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input', 'safe'])
                self.scan_sort(source, 'xss')
                source = ('let saved = "safe"; '
                          f'[[req.query.html]].{method}(values => {{ values.forEach(value => {{ saved = value; }}); '
                          f'return {result}; }}); res.send(saved);')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')

    def test_predicates_keep_native_identity_own_methods_and_argument_order(self):
        for method in ('some', 'every'):
            with self.subTest(method=method):
                source = ('const box = {html:"safe"}; const items = [req.query.html]; '
                          f'items.{method} = function(callback) {{ return "safe"; }}; '
                          f'res.send(items.{method}(value => {{ box.html = value; }})); res.send(box.html);')
                self.assert_runtime_sends(source, ['safe', 'safe'])
                self.scan_sort(source)
                source = ('const items = ["safe"]; '
                          f'items.{method} = function() {{ return req.query.html; }}; '
                          f'res.send(items.{method}(() => true));')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')
                source = ('const box = {html:req.query.html}; const items = ["safe"]; '
                          f'function replace() {{ items.{method} = function() {{ box.html = req.query.html; }}; '
                          'return {}; } '
                          f'items.{method}(value => {{ box.html = value; return true; }}, replace()); res.send(box.html);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan_sort(source)
                self.scan_sort('const items = [req.query.html]; items.constructor = foreign; '
                               f'items.{method}(value => {{ res.send(value); return true; }});', 'xss')

    def test_predicates_transport_sibling_arrow_captures_without_executing_unused_callbacks(self):
        for method, result in (('some', 'false'), ('every', 'true')):
            for values, expected, rules in (('[req.query.html]', 'review-input', ('xss',)), ('[]', 'safe', ())):
                with self.subTest(method=method, values=values):
                    source = ('const box = {html:"safe"}; '
                              f'const visit = value => {{ box.html = value; return {result}; }}; '
                              f'function run(items) {{ return items.{method}(visit); }} '
                              f'run({values}); res.send(box.html);')
                    self.assert_runtime_sends(source, [expected])
                    self.scan_sort(source, *rules)
            source = ('const box = {html:"safe"}; '
                      'function unused(value) { box.html = req.query.html; } '
                      f'function run(items) {{ const local = unused; return items.{method}(value => true); }} '
                      'run(["safe"]); res.send(box.html);')
            self.assert_runtime_sends(source, ['safe'])
            self.scan_sort(source)

    def test_predicates_transport_function_expression_alias_and_parameter_captures(self):
        for method, result in (('some', 'false'), ('every', 'true')):
            body = f'{{ box.html = value; return {result}; }}'
            for label, declaration, target, parameter in (
                    ('expression', f'const visit = function(value) {body};', 'visit', ''),
                    ('named-expression', f'const visit = function write(value) {body};', 'visit', ''),
                    ('alias', f'const visit = value => {body}; const alias = visit;', 'alias', ''),
                    ('parameter', f'const visit = value => {body};', 'predicate', ', predicate')):
                with self.subTest(method=method, callback=label):
                    argument = ', visit' if parameter else ''
                    source = ('const box = {html:"safe"}; ' + declaration
                              + f'function run(items{parameter}) {{ return items.{method}({target}); }} '
                              + f'run([req.query.html]{argument}); res.send(box.html); '
                              + f'run(["safe"]{argument}); res.send(box.html);')
                    self.assert_runtime_sends(source, ['review-input', 'safe'])
                    self.scan_sort(source, 'xss')

    def test_predicates_keep_unknown_callbacks_and_property_protocols_explicit(self):
        for method in ('some', 'every'):
            for callback in ('external', 'async value => value', 'function* (value) { yield value; }'):
                with self.subTest(method=method, callback=callback):
                    self.scan_sort('res.send(req.query.html); '
                                   f'["safe"].{method}({callback});', 'xss',
                                   partial=f'Array.{method}.*synchronous callback')
            for change in ('items[unknown] = external;', f'items.{method} = external;',
                           f'Array.prototype.{method} = external;', 'Object.setPrototypeOf(items, foreign);'):
                with self.subTest(method=method, change=change):
                    self.scan_sort('res.send(req.query.html); const items = ["safe"]; ' + change
                                   + f'items.{method}(value => true);', 'xss', partial=f'Array.{method}|Own method')
            self.scan_sort('res.send(req.query.html); const items = [...unknown]; '
                           f'items.{method}(value => true);', 'xss', partial=f'Array.{method}.*finite')

    def test_predicates_preserve_escaped_callbacks_and_sparse_maximum_extent(self):
        for method in ('some', 'every'):
            with self.subTest(method=method):
                self.scan_sort(f'let saved; [].{method}(saved = () => {{ res.send(req.query.html); }}); saved();', 'xss')
                self.scan_sort('const items = []; items.length = 4294967294; items[4294967293] = req.query.html; '
                               f'items.{method}(value => {{ res.send(value); return true; }});', 'xss')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_predicates_public_values_exceptions_and_short_circuit_status(self):
        cases = (
            ('effects', 'const box={html:"safe"};\n'
             'function write(value){box.html=value;return true;}\n'
             'function run(items){return items.every(write);}\nrun([req.query.html]);\n'
             'res.send(box.html);\ntry{\n[req.query.html].some(value=>{throw value;});\n'
             '}catch(error){\nres.send(error);\n}\n',
             [('javascript.taint.xss', line, 1) for line in (5, 9)], False),
            ('clean', 'let saved="safe";\n'
             '["safe",req.query.html].some(value=>{saved=value;return true;});\nres.send(saved);\n'
             '["safe",req.query.html].every(value=>{saved=value;return false;});\nres.send(saved);\n'
             'res.send([req.query.html].some(value=>value));\n'
             'res.send([req.query.html].every(value=>value));\n'
             '[].every(()=>{res.send(req.query.html);return true;});\n', [], False),
            ('partial', 'res.send(req.query.html);\nconst items=["safe"];\nitems.some(external);\n',
             [('javascript.taint.xss', 1, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-predicates-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            if name != 'partial':
                self.assert_runtime_sends(source, ['review-input', 'review-input'] if name == 'effects'
                                          else ['safe', 'safe', True, True])
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Array.some')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_predicates_public_cache_edit_and_suppression(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-predicates-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('let saved="safe";\n'
                  '[req.query.html].some(value=>{saved=value;return true;});\nres.send(saved);\n')
        clean = unsafe.replace('[req.query.html]', '["safe"]')
        suppressed = unsafe.replace('res.send(saved);', 'res.send(saved); // ubs:ignore')
        for index, (source, expected) in enumerate((
                (unsafe, [('javascript.taint.xss', 3, 1)]),
                (unsafe, [('javascript.taint.xss', 3, 1)]),
                (clean, []), (suppressed, []), (unsafe, [('javascript.taint.xss', 3, 1)]))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                report = self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                                expected=expected, cache=True)
                self.assertEqual(report['profile']['cache_hits'], 1 if index in (1, 4) else 0, report)

    def test_reduce_executes_captured_writes_and_uses_returned_accumulator(self):
        for method in ('reduce', 'reduceRight'):
            with self.subTest(method=method):
                source = ('let saved = "safe"; const box = {html:"safe"}; '
                          f'const out = [req.query.html].{method}((acc, value) => {{ '
                          'saved = value; box.html = value; }, "seed"); '
                          'res.send(saved); res.send(box.html); res.send(out);')
                self.assert_runtime_sends(source, ['review-input', 'review-input', None])
                self.scan_sort(source, 'xss', 'xss')

    def test_reduce_preserves_accumulator_writes_and_borrowed_identity(self):
        for method in ('reduce', 'reduceRight'):
            with self.subTest(method=method):
                source = ('const box = {html:"safe", label:"safe"}; '
                          f'const out = [req.query.html].{method}((acc, value) => {{ '
                          'acc.html = value; return acc; }, box); '
                          'res.send(box.html); res.send(out.html); res.send(out.label);')
                self.assert_runtime_sends(source, ['review-input', 'review-input', 'safe'])
                self.scan_sort(source, 'xss', 'xss')
                source = ('const box = {html:"safe"}; '
                          f'const out = ["value"].{method}((acc, value) => acc, box); '
                          'out.html = req.query.html; res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')
                source = ('const box = {html:req.query.html}; '
                          f'const out = ["safe"].{method}((acc, value) => {{ '
                          'acc.html = value; return acc; }, box); res.send(box.html); res.send(out.html);')
                self.assert_runtime_sends(source, ['safe', 'safe'])
                self.scan_sort(source)

    def test_reduce_uses_direction_and_distinguishes_omitted_seed(self):
        for method, expected, rules in (('reduce', 'safe', ()),
                                        ('reduceRight', 'review-input', ('xss',))):
            with self.subTest(method=method):
                source = (f'const out = [req.query.html, "safe"].{method}((acc, value) => value); '
                          'res.send(out);')
                self.assert_runtime_sends(source, [expected])
                self.scan_sort(source, *rules)
        for method in ('reduce', 'reduceRight'):
            for seed, expected, rules in (('', 'seed', ()),
                                          (', undefined', 'review-input', ('xss',))):
                with self.subTest(method=method, seed=seed):
                    source = (f'const out = ["seed"].{method}((acc, value) => req.query.html{seed}); '
                              'res.send(out);')
                    self.assert_runtime_sends(source, [expected])
                    self.scan_sort(source, *rules)

    def test_reduce_constant_replacement_and_sanitizer_domains(self):
        for method in ('reduce', 'reduceRight'):
            for callback, rules in (
                ('(acc, value) => "safe"', ()),
                ('(acc, value) => DOMPurify.sanitize(value)', ('eval', 'sql', 'command')),
                ('(acc, value) => value', ('xss', 'eval', 'sql', 'command')),
            ):
                with self.subTest(method=method, callback=callback):
                    self.scan_sort(f'const out = [req.query.html].{method}({callback}, req.query.html); '
                                   'res.send(out); eval(out); db.query(out); shell.exec(out);', *rules)
            source = (f'const out = [req.query.html].{method}((acc, value) => acc, "safe"); '
                      'res.send(out);')
            self.assert_runtime_sends(source, ['safe'])
            self.scan_sort(source)

    def test_reduce_empty_and_sparse_arrays_skip_callback_execution(self):
        for method in ('reduce', 'reduceRight'):
            for initial, seed in (('[]', ', req.query.html'), ('[,,]', ', req.query.html'),
                                  ('[,req.query.html,,]', '')):
                with self.subTest(method=method, initial=initial, seed=seed):
                    source = ('let saved = "safe"; '
                              f'const out = {initial}.{method}((acc, value) => {{ '
                              'saved = req.query.html; res.send(req.query.html); return "safe"; }'
                              + seed + '); res.send(saved); res.send(out);')
                    self.assert_runtime_sends(source, ['safe', 'review-input'])
                    self.scan_sort(source, 'xss')

    def test_reduce_without_seed_throws_on_empty_arrays_and_holes(self):
        for method, initial in itertools.product(('reduce', 'reduceRight'), ('[]', '[,,]')):
            with self.subTest(method=method, initial=initial):
                source = ('let saved = "safe"; try { '
                          f'{initial}.{method}((acc, value) => {{ res.send(req.query.html); return value; }}); '
                          'saved = req.query.html; } catch (error) { res.send("caught"); } res.send(saved);')
                self.assert_runtime_sends(source, ['caught', 'safe'])
                self.scan_sort(source)
                source = ('try { ' + initial + f'.{method}((acc, value) => value); '
                          '} catch (error) { res.send(req.query.html); }')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')

    def test_reduce_callback_throws_preserve_prior_writes_and_thrown_values(self):
        for method in ('reduce', 'reduceRight'):
            with self.subTest(method=method):
                source = ('const box = {html:"safe"}; try { '
                          f'[req.query.html].{method}((acc, value) => {{ '
                          'acc.html = value; throw value; }, box); box.html = "safe"; '
                          '} catch (error) { res.send(box.html); res.send(error); }')
                self.assert_runtime_sends(source, ['review-input', 'review-input'])
                self.scan_sort(source, 'xss', 'xss')

    def test_reduce_reads_live_future_slots_and_snapshots_length(self):
        for method, initial, future in (('reduce', '["safe", req.query.html]', 1),
                                         ('reduceRight', '[req.query.html, "safe"]', 0)):
            with self.subTest(method=method):
                source = (f'const items = {initial}; const out = items.{method}((acc, value, index, source) => {{ '
                          f'source[{future}] = "safe"; source.push(req.query.html); return value; '
                          '}, "seed"); res.send(out);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan_sort(source)
                source = (f'const items = {initial}; const out = items.{method}((acc, value, index, source) => {{ '
                          f'delete source[{future}]; return value; }}, "seed"); res.send(out);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan_sort(source)
        for method, initial, future in (('reduce', '["safe", ,]', 1),
                                         ('reduceRight', '[, "safe"]', 0)):
            with self.subTest(method=method, insertion=True):
                source = (f'const items = {initial}; const out = items.{method}((acc, value, index, source) => {{ '
                          f'source[{future}] = req.query.html; return value; }}, "seed"); res.send(out);')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')

    def test_reduce_optional_slots_keep_seed_and_first_element_alternatives(self):
        for method, initial, index in (('reduce', '[, "safe"]', 0),
                                        ('reduceRight', '["safe", ,]', 1)):
            with self.subTest(method=method):
                source = (f'const items = {initial}; if (flag) items[{index}] = req.query.html; '
                          f'const out = items.{method}((acc, value) => acc); res.send(out);')
                for flag, expected in (('true', 'review-input'), ('false', 'safe')):
                    self.assert_runtime_sends(f'const flag = {flag}; ' + source, [expected])
                self.scan_sort(source, 'xss')
        for method in ('reduce', 'reduceRight'):
            for seed in ('', ', req.query.html'):
                with self.subTest(method=method, seed=seed):
                    source = ('const items = [,]; if (flag) items[0] = req.query.html; try { '
                              f'const out = items.{method}((acc, value) => "safe"{seed}); res.send(out); '
                              '} catch (error) { res.send("empty"); }')
                    for flag, expected in (('true', 'safe' if seed else 'review-input'),
                                            ('false', 'review-input' if seed else 'empty')):
                        self.assert_runtime_sends(f'const flag = {flag}; ' + source, [expected])
                    self.scan_sort(source, 'xss')

    def test_reduce_binds_all_four_arguments_without_flattening(self):
        for method in ('reduce', 'reduceRight'):
            with self.subTest(method=method):
                source = ('const box = {html:"seed"}; const items = [req.query.html]; '
                          f'const out = items.{method}((acc, value, index, source) => [acc, value, index, source], box); '
                          'res.send(out[0].html); res.send(out[1]); res.send(out[2]); res.send(out[3][0]);')
                self.assert_runtime_sends(source, ['seed', 'review-input', 0, 'review-input'])
                self.scan_sort(source, 'xss', 'xss')

    def test_reduce_resolves_named_callbacks_and_helper_contexts(self):
        for method in ('reduce', 'reduceRight'):
            with self.subTest(method=method):
                source = ('function write(acc, value) { acc.html = value; return acc; } '
                          f'function collect(items, target) {{ return items.{method}(write, target); }} '
                          'const dirty = {html:"safe"}; const clean = {html:"safe"}; '
                          'collect([req.query.html], dirty); collect(["safe"], clean); '
                          'res.send(dirty.html); res.send(clean.html);')
                self.assert_runtime_sends(source, ['review-input', 'safe'])
                self.scan_sort(source, 'xss')

    def test_reduce_composes_literal_computed_postfix_and_nested_calls(self):
        for source in (
            'res.send([req.query.html].reduce((acc, value) => value, "seed"));',
            'function make() { return [req.query.html]; } res.send(make().reduceRight((acc, value) => value));',
            'const items = [req.query.html]; const out = items["reduce"]((acc, value) => value, "seed"); res.send(out);',
            'const out = ([req.query.html]).map(value => value).reduceRight((acc, value) => [value], []); res.send(out[0]);',
            'const box = {html:"safe"}; ["safe"].reduce((acc, value) => [req.query.html].reduceRight((inner, item) => { box.html = item; return inner; }, acc), "seed"); res.send(box.html);',
        ):
            with self.subTest(source=source):
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')

    def test_reduce_keeps_evaluated_receiver_before_seed_side_effects(self):
        for method in ('reduce', 'reduceRight'):
            with self.subTest(method=method):
                source = ('let items = ["safe"]; '
                          f'const out = items.{method}((acc, value) => value, items = [req.query.html]); '
                          'res.send(out); res.send(items[0]);')
                self.assert_runtime_sends(source, ['safe', 'review-input'])
                self.scan_sort(source, 'xss')
                source = ('const items = ["safe"]; '
                          f'const out = items.{method}((acc, value) => value, (items[0] = req.query.html, "seed")); '
                          'res.send(out);')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan_sort(source, 'xss')

    def test_reduce_preserves_sparse_extents_without_dense_visitation(self):
        for method in ('reduce', 'reduceRight'):
            with self.subTest(method=method):
                self.scan_sort('const items = []; items.length = 4294967294; '
                               f'items[4000000000] = req.query.html; const out = items.{method}((acc, value) => value); '
                               'res.send(out);', 'xss')

    def test_reduce_honors_selected_own_methods_and_ignores_species(self):
        for method in ('reduce', 'reduceRight'):
            for returned, expected, rules in (('"safe"', 'safe', ()),
                                              ('req.query.html', 'review-input', ('xss',))):
                with self.subTest(method=method, returned=returned):
                    source = ('const items = [req.query.html]; '
                              f'items.{method} = function(callback) {{ return {returned}; }}; '
                              f'const out = items.{method}((acc, value) => req.query.html); res.send(out);')
                    self.assert_runtime_sends(source, [expected])
                    self.scan_sort(source, *rules)
            self.scan_sort('const items = [req.query.html]; items.constructor = foreign; '
                           f'const out = items.{method}((acc, value) => value); res.send(out);', 'xss')

    def test_reduce_unknown_callback_and_property_protocols_stay_explicit(self):
        for method in ('reduce', 'reduceRight'):
            for callback in ('external', 'async (acc, value) => value',
                              'function* (acc, value) { yield value; }'):
                with self.subTest(method=method, callback=callback):
                    self.scan_sort('res.send(req.query.html); const items = ["safe"]; '
                                   f'items.{method}({callback}, "seed");', 'xss', partial=f'Array.{method}')
            for setup in ('Object.defineProperty(items, "0", {get() { return req.query.html; }});',
                          'Object.setPrototypeOf(items, foreign);', f'Array.prototype.{method} = external;',
                          f'items.{method} = external;', 'items[method] = external;'):
                with self.subTest(method=method, setup=setup):
                    self.scan_sort('res.send(req.query.html); const items = ["safe"]; ' + setup
                                   + f'items.{method}((acc, value) => value, "seed");',
                                   'xss', partial=f'{method}|Object[.]')
            self.scan_sort('res.send(req.query.html); const items = [...unknown]; '
                           f'items.{method}((acc, value) => "safe", "seed");', 'xss', partial=f'Array.{method}')

    def test_reduce_callback_defaults_this_and_escaped_closures_stay_explicit(self):
        for method in ('reduce', 'reduceRight'):
            for callback in ('(acc = req.query.html, value) => res.send(acc)',
                              '(acc, value = req.query.html) => res.send(value)'):
                with self.subTest(method=method, callback=callback):
                    self.scan_sort(f'[undefined].{method}({callback}, undefined);',
                                   'xss', partial=f'Array.{method}.*default')
            self.scan_sort('res.send(req.query.html); const items = ["safe"]; '
                           f'items.{method}(function(acc, value) {{ return this.html; }}, {{html:"safe"}});',
                           'xss', partial=f'Array.{method}.*this')
            self.scan_sort(f'const out = [req.query.html].{method}((acc, value) => () => value, "seed"); '
                           'res.send(out());', partial='escaped closure')

    def test_reduce_does_not_hide_escaped_empty_callback_entrypoints(self):
        for method in ('reduce', 'reduceRight'):
            with self.subTest(method=method):
                self.scan_sort(f'let saved; [].{method}(saved = () => {{ '
                               'res.send(req.query.html); return "safe"; }, "seed"); external(saved);', 'xss')
                self.scan_sort(f'[].{method}(() => {{ res.send(req.query.html); return "safe"; }}, "seed"); '
                               'external("safe");')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_reduce_public_values_exceptions_and_partial_status(self):
        cases = (
            ('effects', 'const box={html:"safe"};\n'
             'const out=[req.query.html].reduce((acc,value)=>{acc.html=value;return acc;},box);\n'
             'res.send(box.html);\nres.send(out.html);\n'
             'const right=[req.query.html,"safe"].reduceRight((acc,value)=>value);\nres.send(right);\n',
             [('javascript.taint.xss', line, 1) for line in (3, 4, 6)], False),
            ('clean', 'const out=[req.query.html].reduce((acc,value)=>"safe",req.query.html);\n'
             'res.send(out);\nlet saved="safe";\n'
             'try {[,,].reduceRight((acc,value)=>value);saved=req.query.html;}catch(error){res.send("caught");}\n'
             'res.send(saved);\n'
             '[].reduce((acc,value)=>{res.send(req.query.html);return value;},"seed");\n', [], False),
            ('partial', 'res.send(req.query.html);\n'
             'const items=["safe"];items.reduce(external,"seed");\n',
             [('javascript.taint.xss', 1, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-reduce-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            if name == 'clean':
                self.assert_runtime_sends(source, ['safe', 'caught', 'safe'])
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Array.reduce')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_reduce_public_cache_edit_and_suppression(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-reduce-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const box={html:"safe"};\n'
                  '[req.query.html].reduce((acc,value)=>{acc.html=value;return acc;},box);\n'
                  'res.send(box.html);\n')
        clean = unsafe.replace('[req.query.html]', '["safe"]')
        suppressed = unsafe.replace('res.send(box.html);', 'res.send(box.html); // ubs:ignore')
        for index, (source, expected) in enumerate((
                (unsafe, [('javascript.taint.xss', 3, 1)]),
                (unsafe, [('javascript.taint.xss', 3, 1)]),
                (clean, []), (suppressed, []), (unsafe, [('javascript.taint.xss', 3, 1)]))):
            with self.subTest(index=index):
                target.write_text(source, encoding='utf-8')
                report = self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                                expected=expected, cache=True)
                self.assertEqual(report['profile']['cache_hits'], 1 if index in (1, 4) else 0, report)

    def test_map_returns_callback_values_in_separate_indexed_slots(self):
        source = ('const items = ["safe", req.query.html];\n'
                  'const out = items.map(value => value);\n'
                  'res.send(out[0]);\nres.send(out[1]);\nres.send(out.length);')
        self.assert_runtime_sends(source, ['safe', 'review-input', 2])
        findings = self.scan(source, 'xss')
        self.assertEqual([finding['line'] for finding in findings], [4])
        source = ('const items = [1]; const out = items.map(value => req.query.html); '
                  'res.send(out[0]);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan(source, 'xss')

    def test_map_keeps_nested_arrays_and_borrowed_object_identity(self):
        source = ('const box = {html: "safe"}; const items = [1]; '
                  'const out = items.map(value => [box]); '
                  'out[0][0].html = req.query.html; res.send(box.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan(source, 'xss')
        source = ('const box = {html: req.query.html, label: "safe"}; '
                  'const items = [box]; const out = items.map(value => value); '
                  'res.send(out[0].label); out[0].html = "safe"; res.send(box.html);')
        self.assert_runtime_sends(source, ['safe', 'safe'])
        self.scan(source)

    def test_map_keeps_constant_results_and_sink_specific_sanitizers_clean(self):
        for mapper, rules in (('value => "safe"', ()),
                              ('value => DOMPurify.sanitize(value)', ('eval', 'sql', 'command')),
                              ('value => value', ('xss', 'eval', 'sql', 'command'))):
            with self.subTest(mapper=mapper):
                self.scan('const items = [req.query.html]; '
                          f'const out = items.map({mapper}); '
                          'res.send(out[0]); eval(out[0]); db.query(out[0]); shell.exec(out[0]);', *rules)

    def test_for_each_executes_captured_writes_and_returns_undefined(self):
        source = ('const box = {html: "safe"}; let saved = "safe"; '
                  'const items = [req.query.html]; '
                  'const out = items.forEach(value => { box.html = value; saved = value; return value; }); '
                  'res.send(box.html); res.send(saved); res.send(out);')
        self.assert_runtime_sends(source, ['review-input', 'review-input', None])
        self.scan(source, 'xss', 'xss')
        self.scan('const items = [{html: req.query.html}]; const box = items[0]; '
                  'items.forEach(value => { value.html = "safe"; }); res.send(box.html);')

    def test_iterating_callbacks_skip_empty_arrays_and_holes(self):
        for method, initial in itertools.product(('map', 'forEach'), ('[]', '[,,]')):
            with self.subTest(method=method, initial=initial):
                source = (f'const items = {initial}; let saved = "safe"; '
                          f'items.{method}(value => {{ saved = req.query.html; '
                          'res.send(req.query.html); return req.query.html; }); res.send(saved);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan(source)
        source = ('const items = [, req.query.html, , "safe"]; '
                  'const out = items.map(value => value); '
                  'res.send(out[0]); res.send(out[1]); res.send(out[2]); '
                  'res.send(out[3]); res.send(out.length);')
        self.assert_runtime_sends(source, [None, 'review-input', None, 'safe', 4])
        self.scan(source, 'xss')

    def test_map_callbacks_snapshot_length_and_read_live_slots(self):
        source = ('const items = [req.query.html, req.query.html]; '
                  'const out = items.map((value, index, source) => { '
                  'source[1] = "safe"; source.push(req.query.html); return value; }); '
                  'res.send(out[0]); res.send(out[1]); res.send(out[2]); res.send(out.length);')
        self.assert_runtime_sends(source, ['review-input', 'safe', None, 2])
        self.scan(source, 'xss')
        source = ('const items = ["safe", ,]; '
                  'const out = items.map((value, index, source) => { '
                  'source[1] = req.query.html; return value; }); res.send(out[1]);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan(source, 'xss')
        source = ('const items = ["safe", req.query.html]; '
                  'const out = items.map((value, index, source) => { '
                  'delete source[1]; return value; }); res.send(out[1]); res.send(out.length);')
        self.assert_runtime_sends(source, [None, 2])
        self.scan(source)

    def test_for_each_reads_new_future_slots_but_not_appended_elements(self):
        source = ('const items = ["safe", ,]; const out = []; '
                  'items.forEach((value, index, source) => { '
                  'source[1] = req.query.html; source.push(req.query.html); out.push(value); }); '
                  'res.send(out[0]); res.send(out[1]); res.send(out[2]);')
        self.assert_runtime_sends(source, ['safe', 'review-input', None])
        self.scan(source, 'xss')

    def test_iterating_callbacks_preserve_throws_and_prior_effects(self):
        for method in ('map', 'forEach'):
            with self.subTest(method=method):
                source = ('const items = [req.query.html]; let saved = "safe"; try { '
                          f'items.{method}(value => {{ saved = value; throw "stop"; }}); '
                          'saved = "safe"; } catch (error) { res.send(saved); }')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan(source, 'xss')
                source = ('const items = [req.query.html]; try { '
                          f'items.{method}(value => {{ throw value; }}); res.send(req.query.html); '
                          '} catch (error) { res.send(error); }')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan(source, 'xss')

    def test_iterating_callbacks_resolve_named_callbacks_and_helper_arguments(self):
        source = ('function wrap(value) { return {html: value}; } '
                  'function transform(items) { return items.map(wrap); } '
                  'const dirty = transform([req.query.html]); const clean = transform(["safe"]); '
                  'res.send(dirty[0].html); res.send(clean[0].html);')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        self.scan(source, 'xss')
        source = ('function transform(items, target) { '
                  'function write(value) { target.html = value; } items.forEach(write); } '
                  'const dirty = {}; const clean = {}; '
                  'transform([req.query.html], dirty); transform(["safe"], clean); '
                  'res.send(dirty.html); res.send(clean.html);')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        self.scan(source, 'xss')

    def test_iterating_callbacks_separate_this_index_and_source_arguments(self):
        source = ('const items = ["safe"]; '
                  'const out = items.map(function(value, index, source) { '
                  'return [this.html, index, source[0]]; }, {html: req.query.html}); '
                  'res.send(out[0][0]); res.send(out[0][1]); res.send(out[0][2]);')
        self.assert_runtime_sends(source, ['review-input', 0, 'safe'])
        self.scan(source, 'xss')
        source = ('const target = {html: "safe"}; const items = [req.query.html]; '
                  'items.forEach(function(value) { this.html = value; }, target); res.send(target.html);')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan(source, 'xss')

    def test_iterating_callbacks_honor_selected_own_methods(self):
        for method in ('map', 'forEach'):
            with self.subTest(method=method):
                self.scan('const items = [req.query.html]; '
                          f'items.{method} = function(callback) {{ return ["safe"]; }}; '
                          f'const out = items.{method}(value => req.query.html); res.send(out[0]);')
                self.scan('const items = ["safe"]; '
                          f'items.{method} = function(callback) {{ return [req.query.html]; }}; '
                          f'const out = items.{method}(value => "safe"); res.send(out[0]);', 'xss')

    def test_map_literal_receivers_computed_methods_and_postfix_chains(self):
        for source in (
            'res.send([1].map(value => req.query.html)[0]);',
            'function make() { return [req.query.html]; } res.send(make().map(value => value)[0]);',
            'const items = [1]; const out = items["map"](value => req.query.html); res.send(out[0]);',
            'const items = [1]; const out = (items).map(value => [req.query.html])[0]'
            '.map(value => value); res.send(out[0]);',
        ):
            with self.subTest(source=source):
                self.assert_runtime_sends(source, ['review-input'])
                self.scan(source, 'xss')

    def test_map_preserves_large_sparse_extent_without_dense_visitation(self):
        self.scan('const items = []; items.length = 4294967294; '
                  'items[4000000000] = req.query.html; const out = items.map(value => value); '
                  'res.send(out[0]); res.send(out[4000000000]); res.send(out.length);', 'xss')

    def test_iterating_callbacks_expose_unknown_protocols_and_async_boundaries(self):
        for method in ('map', 'forEach'):
            for callback in ('async value => value', 'function* (value) { yield value; }', 'external'):
                with self.subTest(method=method, callback=callback):
                    self.assert_fill_partial('res.send(req.query.html); const items = ["safe"]; '
                        f'items.{method}({callback});', 'xss', reason=f'Array.{method}')
            for setup in ('Object.defineProperty(items, "0", {get() { return req.query.html; }});',
                          'Object.setPrototypeOf(items, foreign);', f'Array.prototype.{method} = external;'):
                with self.subTest(method=method, setup=setup):
                    self.assert_fill_partial('res.send(req.query.html); const items = ["safe"]; '
                        + setup + f'items.{method}(value => value);', 'xss', reason=f'{method}|Object[.]')
            self.assert_fill_partial('res.send(req.query.html); const items = [...unknown]; '
                f'items.{method}(value => "safe");', 'xss', reason=f'Array.{method}')
        self.assert_fill_partial('res.send(req.query.html); const items = ["safe"]; '
            'items.constructor = foreign; items.map(value => value);', 'xss', reason='Array.map')
        # forEach never invokes ArraySpeciesCreate; constructor overrides alone
        # do not affect its iteration or prove arbitrary callback execution.
        self.scan('const items = [req.query.html]; items.constructor = foreign; '
                  'items.forEach(value => res.send(value));', 'xss')

    def test_iterating_callbacks_do_not_hide_escaped_entrypoints(self):
        for method in ('map', 'forEach'):
            for escape in ('external(saved);', 'external(0, {callback: saved});'):
                with self.subTest(method=method, escape=escape):
                    self.scan(f'let saved; [].{method}(saved = () => {{ '
                              'res.send(req.query.html); return "safe"; }); ' + escape, 'xss')
            self.scan(f'[].{method}(value => {{ res.send(req.query.html); return "safe"; }}); '
                      'external(0, "safe");')

    def test_iterating_callbacks_compose_nested_native_visits(self):
        for outer, inner in itertools.product(('map', 'forEach', 'flatMap'), repeat=2):
            with self.subTest(outer=outer, inner=inner):
                source = ('const box = {html: "safe"}; '
                          f'["safe"].{outer}(value => [req.query.html].{inner}'
                          '(item => { box.html = item; })); res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input'])
                if outer == 'flatMap':
                    # The existing flatMap result-shape boundary still applies
                    # to a call expression. It must retain the nested write's
                    # finding even though flattening that return is incomplete.
                    self.assert_fill_partial(source, 'xss', reason='flatMap.*(?:alternatives|shape)')
                else:
                    self.scan(source, 'xss')

    def test_nested_native_captures_follow_named_callbacks_without_running_unused_ones(self):
        for method in ('map', 'forEach'):
            with self.subTest(method=method):
                source = ('const box = {html: "safe"}; '
                          'function visit(items) { const write = value => { box.html = value; }; '
                          f'items.{method}(write); }} visit([req.query.html]); res.send(box.html);')
                self.assert_runtime_sends(source, ['review-input'])
                self.scan(source, 'xss')
                source = ('const box = {html: "safe"}; '
                          'function visit(items) { const write = value => { box.html = req.query.html; }; '
                          f'items.{method}(write); }} visit([]); res.send(box.html);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan(source)

    def test_map_returned_closures_keep_explicit_capture_boundary(self):
        source = ('const callbacks = [req.query.html].map(value => () => value); '
                  'res.send(callbacks[0]());')
        self.assert_runtime_sends(source, ['review-input'])
        self.assert_fill_partial(source, reason='escaped closure')

    def test_iterating_callback_defaults_and_length_changes_stay_explicit(self):
        for method in ('map', 'forEach'):
            with self.subTest(method=method):
                self.assert_fill_partial('const items = [undefined]; '
                    f'items.{method}((value = req.query.html) => res.send(value));',
                    'xss', reason=f'{method}.*default')
                self.assert_fill_partial('res.send(req.query.html); const items = [1, 2]; '
                    f'items.{method}((value, index, source) => {{ source.length = unknown; return value; }});',
                    'xss', reason=f'{method}.*length')

    def iterating_callbacks_public_formats(self, group):
        cases = (
            ('map-source', 'const items=[1];\nconst out=items.map(value=>req.query.html);\n'
             'res.send(out[0]);\n', [("javascript.taint.xss", 3, 1)], None),
            ('foreach-source', 'const box={html:"safe"};\nconst items=[req.query.html];\n'
             'items.forEach(value=>{box.html=value;});\nres.send(box.html);\n',
             [("javascript.taint.xss", 4, 1)], None),
            ('map-clean', 'const items=[req.query.html];\nconst out=items.map(value=>"safe");\n'
             'res.send(out[0]);\n', [], None),
            ('empty-callback', 'let html="safe";\nconst items=[];\n'
             'items.forEach(value=>{html=req.query.html;});\nres.send(html);\n', [], None),
            ('map-protocol', 'const items=["safe"];\nitems.constructor=external;\n'
             'items.map(value=>value);\nres.send(req.query.html);\n',
             [("javascript.taint.xss", 4, 1)], 'Array.map'),
            ('foreach-unknown', 'const items=["safe"];\n'
             'items.forEach(external);\nres.send(req.query.html);\n',
             [("javascript.taint.xss", 3, 1)], 'Array.forEach'),
        )
        self.assertIn(group, ('values', 'boundaries'))
        cases = cases[:3] if group == 'values' else cases[3:]
        artifacts = ROOT / 'test-suite/artifacts/javascript-array-callbacks-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix=group + '-', dir=artifacts))
        for name, source, expected, reason in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=reason is not None,
                                            partial_reason=reason)

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_iterating_callbacks_public_values_and_selected_files(self):
        self.iterating_callbacks_public_formats('values')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_iterating_callbacks_public_boundaries_and_empty_arrays(self):
        self.iterating_callbacks_public_formats('boundaries')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_iterating_callbacks_public_cache_edit_and_suppression(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-array-callbacks-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const items=[1];\nconst out=items.map(value=>req.query.html);\n'
                  'res.send(out[0]);\n')
        clean = unsafe.replace('value=>req.query.html', 'value=>"safe"')
        suppressed = unsafe.replace('res.send(out[0]);', 'res.send(out[0]); // ubs:ignore')
        for index, (source, expected) in enumerate((
                (unsafe, [("javascript.taint.xss", 3, 1)]),
                (unsafe, [("javascript.taint.xss", 3, 1)]),
                (clean, []), (suppressed, []), (unsafe, [("javascript.taint.xss", 3, 1)]))):
            with self.subTest(index=index):
                if index != 1:
                    target.write_text(source, encoding='utf-8')
                report = self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                                expected=expected, cache=True)
                if index == 1:
                    self.assertEqual(report['profile']['cache_hits'], 1, report)
                elif index < 4:
                    self.assertEqual(report['profile']['cache_hits'], 0, report)

    def test_flatmap_preserves_source_returns_and_exact_positions(self):
        source = ('const items = [1]; const out = items.flatMap(value => ["safe", req.query.html]); '
                  'res.send(out[0]); res.send(out[1]); res.send(out.length);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['safe', 'review-input', 2])
        self.scan('const items = [req.query.html, "safe"]; '
                  'const out = items.flatMap(value => [value]); '
                  'res.send(out[0]); res.send(out[1]);', 'xss')

    def test_flat_preserves_selected_values_and_clean_metadata(self):
        source = ('const items=[[req.query.html],["safe"]]; const out=items.flat(); '
                  'res.send(out[0]); res.send(out[1]); res.send(out[2]); res.send(out.length);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe', None, 2])
        self.scan('const out=[[DOMPurify.sanitize(req.query.html)]].flat(); '
                  'res.send(out[0]); eval(out[0]); db.query(out[0]); shell.exec(out[0]);',
                  'eval', 'sql', 'command')

    def test_flat_depth_and_holes_follow_native_index_order(self):
        for argument in ('', 'undefined', '1', '1.9', 'true'):
            source = ('const items=[,["safe",,req.query.html],,["fixed"]]; '
                      f'const out=items.flat({argument}); '
                      'res.send(out[0]); res.send(out[1]); res.send(out[2]); res.send(out.length);')
            with self.subTest(argument=argument):
                self.scan(source, 'xss')
                self.assert_runtime_sends(source, ['safe', 'review-input', 'fixed', 3])
        for argument in ('0', '-1', 'null', 'false', 'NaN', '-Infinity'):
            source = ('const items=[,[req.query.html],,"safe"]; '
                      f'const out=items.flat({argument}); '
                      'res.send(out[0][0]); res.send(out[1]); res.send(out.length);')
            with self.subTest(argument=argument):
                self.scan(source, 'xss')
                self.assert_runtime_sends(source, ['review-input', 'safe', 2])
        for argument in ('2', 'Infinity'):
            source = ('const box={html:req.query.html}; const items=[[[box]]]; '
                      f'const out=items.flat({argument}); res.send(out[0].html);')
            with self.subTest(argument=argument):
                self.scan(source, 'xss')
                self.assert_runtime_sends(source, ['review-input'])

    def test_flat_preserves_nested_aliases_and_copies_outer_slots(self):
        source = ('const box={html:"safe"}; const inside=[box]; const items=[inside]; '
                  'const out=items.flat(); out[0].html=req.query.html; '
                  'res.send(box.html); res.send(inside[0].html);')
        self.scan(source, 'xss', 'xss')
        self.assert_runtime_sends(source, ['review-input', 'review-input'])
        source = ('const inside=[req.query.html]; const out=[inside].flat(); '
                  'out[0]="safe"; res.send(inside[0]); res.send(out[0]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        source = ('const inside=["safe"]; const out=[inside].flat(0); '
                  'out[0][0]=req.query.html; res.send(inside[0]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])

    def test_flat_only_flattens_arrays_and_ignores_named_properties(self):
        source = ('const box={0:req.query.html,length:1,html:"safe"}; '
                  'const items=[box,"fixed",["clean"]]; items.note=req.query.html; '
                  'const out=items.flat(); res.send(out[0].html); res.send(out[0][0]); '
                  'res.send(out[1]); res.send(out[2]); res.send(out.note); res.send(out.length);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['safe', 'review-input', 'fixed', 'clean', None, 3])

    def test_flat_repeated_arrays_are_flattened_per_occurrence(self):
        source = ('const box={html:req.query.html}; const inner=[box]; '
                  'const out=[inner,inner].flat(); '
                  'res.send(out[0].html); res.send(out[1].html); res.send(out.length);')
        self.scan(source, 'xss', 'xss')
        self.assert_runtime_sends(source, ['review-input', 'review-input', 2])
        source = ('const box={html:req.query.html}; const items=[box]; items.push(items); '
                  'const out=items.flat(2); res.send(out[0].html); '
                  'res.send(out[1].html); res.send(out[2].html);')
        self.scan(source, 'xss', 'xss', 'xss')
        self.assert_runtime_sends(source, ['review-input', 'review-input', 'review-input'])

    def test_flat_helpers_and_postfix_chains_preserve_identity(self):
        source = ('function flatten(items) {return items.flat();} '
                  'const dirty=flatten([[req.query.html]]); const clean=flatten([["safe"]]); '
                  'res.send(dirty[0]); res.send(clean[0]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        self.scan('res.send([[req.query.html]].flat()[0]);', 'xss')
        self.scan('res.send(([[req.query.html]]).flat()[0]);', 'xss')
        self.scan('function make(){return [[[req.query.html]]];} '
                  'res.send(make().flat().flat()[0]);', 'xss')
        self.scan('const items=[[[req.query.html]]]; res.send(items["flat"]().flat()[0]);', 'xss')

    def test_flat_literal_shape_proofs_survive_aliases_and_captured_helpers(self):
        source = ('function flatten(label,box) { const saved=label; '
                  'function values(){return [saved,[box]];} return values().flat(Infinity); } '
                  'const dirty=flatten("fixed",{html:req.query.html}); '
                  'const clean=flatten("fixed",{html:"safe"}); '
                  'res.send(dirty[0]); res.send(dirty[1].html); res.send(clean[1].html);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['fixed', 'review-input', 'safe'])

    def test_flat_sparse_arrays_do_not_expand_absent_slots(self):
        self.scan('const inner=[]; inner.length=4294967294; inner[4000000000]=req.query.html; '
                  'const items=[]; items.length=4294967294; items[4000000000]=inner; '
                  'const out=items.flat(); res.send(out[0]); res.send(out[1]); res.send(out.length);', 'xss')

    def test_flat_overrides_and_captured_native_method_remain_distinct(self):
        self.scan('const items=[[req.query.html]]; items.flat=function(){return ["safe"];}; '
                  'res.send(items.flat()[0]);')
        self.scan('const items=[["safe"]]; items.flat=function(){return [req.query.html];}; '
                  'res.send(items.flat()[0]);', 'xss')
        source = ('const items=[[req.query.html]]; '
                  'const out=items.flat(1,items.flat=function(){return ["safe"];}); '
                  'res.send(out[0]); res.send(items.flat()[0]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe'])

    def test_flat_depth_coercion_and_native_protocols_stay_explicit(self):
        for argument in ('unknown', '{valueOf: external}', '1n', '...unknown'):
            with self.subTest(argument=argument):
                self.assert_fill_partial('res.send(req.query.html); const items=[["safe"]]; '
                                         f'items.flat({argument});', 'xss', reason='Array.flat')
        for setup in ('items.constructor=custom;',
                      'Object.defineProperty(items,"0",{get(){return [req.query.html];}});',
                      'Object.setPrototypeOf(items,foreign);',
                      'Array.prototype.flat=external;',
                      'Array.prototype[0]=[req.query.html];'):
            with self.subTest(setup=setup):
                self.assert_fill_partial('res.send(req.query.html); const items=[["safe"]]; '
                                         + setup + 'items.flat();', 'xss', reason='flat|Object[.]')

    def test_flat_mixed_value_shapes_cannot_certify_output_positions(self):
        source = ('const flag=false; const selected=flag ? [] : "safe"; '
                  'const out=[selected,[req.query.html]].flat(); res.send(out[0]); res.send(out[1]);')
        self.assert_fill_partial(source, 'xss', 'xss', reason='Array.flat.*shape')
        self.assert_runtime_sends(source, ['safe', 'review-input'])
        source = ('function selected(flag){if(flag)return [];return "safe";} '
                  'const out=[selected(false),[req.query.html]].flat(); res.send(out[1]);')
        self.assert_fill_partial(source, 'xss', reason='Array.flat.*shape')
        self.assert_fill_partial('const out=[req.query.values,"safe"].flat(); res.send(out[1]);',
                                 'xss', reason='Array.flat.*shape')
        for initial, operator, replacement in (('[]', '&&=', '"safe"'),
                                                ('"safe"', '||=', '[]'),
                                                ('"safe"', '??=', '[]')):
            source = (f'let selected={initial}; '
                      f'const out=[selected {operator} {replacement},[req.query.html]].flat(); '
                      'res.send(out[1]);')
            with self.subTest(operator=operator):
                self.assert_runtime_sends(source, ['review-input'])
                self.assert_fill_partial(source, 'xss', reason='Array.flat.*shape')

    def test_flat_cycles_and_unknown_extents_remain_incomplete(self):
        self.assert_fill_partial('res.send(req.query.html); const items=[]; items.push(items); '
                                 'items.flat(Infinity);', 'xss', reason='Array.flat.*cycle')
        self.assert_fill_partial('res.send(req.query.html); const inner=[...unknown]; '
                                 '[inner].flat();', 'xss', reason='Array.flat.*extent')

    def test_flat_repeated_expansion_obeys_shared_work_budget(self):
        source = 'const box={html:req.query.html}; const level0=[box]; ' + ' '.join(
            f'const level{index}=[level{index-1},level{index-1}];' for index in range(1, 21))
        self.assert_fill_partial(source + ' level20.flat(Infinity); res.send("safe");', reason='work limit')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_flat_public_json_sarif_selection_and_partial(self):
        cases = (
            ('alias', 'const box={html:"safe"};\n'
             'const items=[[box],[{html:req.query.html}]];\n'
             'const out=items.flat();\nout[0].html=req.query.html;\n'
             'res.send(box.html);\nres.send(out[1].html);\n',
             [('javascript.taint.xss', 5, 1), ('javascript.taint.xss', 6, 1)], False),
            ('clean', 'const out=[[req.query.html],["safe"]].flat();\n'
             'res.send(out[1]);\nres.send(out.length);\n', [], False),
            ('partial', 'res.send(req.query.html);\nconst items=[["safe"]];\n'
             'items.flat({valueOf:external});\n', [('javascript.taint.xss', 1, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-array-flat-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Array.flat')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_flat_public_cache_edits_suppression_and_partial_nonreuse(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-array-flat-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = 'const out=[[req.query.html],["safe"]].flat();\nres.send(out[0]);\n'
        clean = unsafe.replace('out[0]', 'out[1]')
        suppressed = unsafe.replace('res.send(out[0]);', 'res.send(out[0]); // ubs:ignore')
        partial = 'res.send(req.query.html);\nconst items=[["safe"]]; items.flat(unknown);\n'
        cases = (
            (unsafe, [('javascript.taint.xss', 2, 1)], False, 0),
            (unsafe, [('javascript.taint.xss', 2, 1)], False, 1),
            (clean, [], False, 0), (suppressed, [], False, 0),
            (unsafe, [('javascript.taint.xss', 2, 1)], False, 1),
            (partial, [('javascript.taint.xss', 1, 1)], True, 0),
            (partial, [('javascript.taint.xss', 1, 1)], True, 0),
        )
        for index, (source, expected, incomplete, cache_hits) in enumerate(cases):
            with self.subTest(index=index):
                if index not in (1, 6):
                    target.write_text(source, encoding='utf-8')
                report = self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                                expected=expected, cache=True, partial=incomplete,
                                                partial_reason='Array.flat')
                self.assertEqual(report['profile']['cache_hits'], cache_hits, report)

    def test_flatmap_flattens_once_and_preserves_object_identity(self):
        source = ('const box = {html: "safe"}; const items = [1]; '
                  'const out = items.flatMap(value => [[box]]); '
                  'out[0][0].html = req.query.html; res.send(box.html);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        source = ('const box = {0: req.query.html, length: 1, html: "safe"}; '
                  'const items = [1]; const out = items.flatMap(value => box); '
                  'res.send(out[0].html); res.send(out[0][0]); res.send(out[1]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['safe', 'review-input', None])

    def test_flatmap_skips_receiver_and_returned_holes(self):
        source = ('const items = [, req.query.html, , "safe"]; '
                  'const out = items.flatMap(value => [, value, ,]); '
                  'res.send(out[0]); res.send(out[1]); res.send(out[2]); res.send(out.length);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe', None, 2])
        for initial in ('[]', '[,,]'):
            self.scan(f'const items = {initial}; let saved = "safe"; '
                      'const out = items.flatMap(value => { saved = req.query.html; '
                      'res.send(req.query.html); return [req.query.html]; }); '
                      'res.send(saved); res.send(out[0]);')

    def test_flatmap_callback_effects_use_live_slots_and_initial_length(self):
        source = ('const items = [req.query.html, req.query.html]; '
                  'const out = items.flatMap((value, index, source) => { '
                  'source[1] = "safe"; source.push(req.query.html); return [value]; }); '
                  'res.send(out[0]); res.send(out[1]); res.send(out[2]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe', None])
        source = ('const items = ["safe", ,]; '
                  'const out = items.flatMap((value, index, source) => { '
                  'source[1] = req.query.html; return [value]; }); res.send(out[1]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan('const items = ["safe", req.query.html]; '
                  'const out = items.flatMap((value, index, source) => { '
                  'source.length = 1; return [value]; }); res.send(out[1]);')

    def test_flatmap_callbacks_keep_captured_and_borrowed_writes(self):
        source = ('let saved = "safe"; const box = {html: "safe"}; const items = [box]; '
                  'const out = items.flatMap(value => { value.html = req.query.html; '
                  'saved = req.query.html; return [value]; }); '
                  'res.send(box.html); res.send(out[0].html); res.send(saved);')
        self.scan(source, 'xss', 'xss', 'xss')
        self.assert_runtime_sends(source, ['review-input', 'review-input', 'review-input'])
        self.scan('const box = {html: req.query.html}; const items = [box]; '
                  'items.flatMap(value => { value.html = "safe"; return []; }); res.send(box.html);')

    def test_flatmap_callbacks_preserve_sanitizer_domains_and_clean_results(self):
        self.scan('const items = [req.query.html]; const out = items.flatMap(value => ["safe"]); '
                  'res.send(out[0]); eval(out[0]); db.query(out[0]); shell.exec(out[0]);')
        self.scan('const items = [req.query.html]; '
                  'const out = items.flatMap(value => [DOMPurify.sanitize(value)]); '
                  'res.send(out[0]); eval(out[0]); db.query(out[0]); shell.exec(out[0]);',
                  'eval', 'sql', 'command')
        self.scan('const items = [req.query.html]; const out = items.flatMap(value => [value]); '
                  'res.send(out[0]); eval(out[0]); db.query(out[0]); shell.exec(out[0]);',
                  'xss', 'eval', 'sql', 'command')

    def test_flatmap_named_callbacks_and_selected_helpers(self):
        source = ('function expand(value) { return [{html: value}]; } '
                  'function transform(items) { return items.flatMap(expand); } '
                  'const dirty = transform([req.query.html]); const clean = transform(["safe"]); '
                  'res.send(dirty[0].html); res.send(clean[0].html);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        self.scan('const callbacks = {expand(value) { return [value]; }}; '
                  'const items = [req.query.html]; const out = items.flatMap(callbacks.expand); '
                  'res.send(out[0]);', 'xss')

    def test_flatmap_this_argument_and_index_are_separate_from_element(self):
        source = ('const items = ["safe"]; const out = items.flatMap(function(value, index, source) { '
                  'return [this.html, index, source[0]]; }, {html: req.query.html}); '
                  'res.send(out[0]); res.send(out[1]); res.send(out[2]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 0, 'safe'])
        self.scan('const items = [req.query.html]; '
                  'const out = items.flatMap(value => ["safe"], {html: req.query.html}); res.send(out[0]);')

    def test_flatmap_exceptions_keep_effects_and_skip_later_work(self):
        source = ('const items = [req.query.html]; let saved = "safe"; try { '
                  'items.flatMap(value => { saved = value; throw "stop"; }); '
                  'saved = "safe"; } catch (error) { res.send(saved); }')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        source = ('const items = [req.query.html]; try { '
                  'items.flatMap(value => { throw value; }); res.send(req.query.html); '
                  '} catch (error) { res.send(error); }')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])

    def test_flatmap_does_not_enumerate_large_sparse_lengths(self):
        self.scan('const items = []; items.length = 4294967294; items[4000000000] = req.query.html; '
                  'const out = items.flatMap(value => [value]); res.send(out[0]); res.send(out[1]);', 'xss')

    def test_flatmap_overrides_keep_selected_function_semantics(self):
        self.scan('const items = [req.query.html]; items.flatMap = function(callback) { return ["safe"]; }; '
                  'const out = items.flatMap(value => [req.query.html]); res.send(out[0]);')
        self.scan('const items = ["safe"]; items.flatMap = function(callback) { return [req.query.html]; }; '
                  'const out = items.flatMap(value => ["safe"]); res.send(out[0]);', 'xss')

    def test_flatmap_literal_receivers_and_postfix_chains(self):
        self.scan('res.send([1].flatMap(value => [req.query.html])[0]);', 'xss')
        self.scan('function make() { return [req.query.html]; } '
                  'const out = make().flatMap(value => [value]); res.send(out[0]);', 'xss')
        self.scan('function make() { return [req.query.html]; } '
                  'res.send(make().flatMap(value => ["safe"])[0]);')
        source = ('const items = [1]; const out = (items).flatMap(value => [[req.query.html]])'
                  '[0].flatMap(value => [value]); res.send(out[0]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])

    def test_flatmap_unsupported_protocols_remain_explicit(self):
        for setup in ('items.constructor = custom;',
                      'Object.defineProperty(items, "0", {get() { return req.query.html; }});',
                      'Object.setPrototypeOf(items, foreign);',
                      'Array.prototype.flatMap = external;'):
            with self.subTest(setup=setup):
                self.assert_fill_partial('res.send(req.query.html); const items = ["safe"]; ' + setup
                    + 'const out = items.flatMap(value => [value]); res.send(out[0]);',
                    'xss', reason='flatMap|Object[.]')
        for callback in ('async value => [value]', 'function* (value) { yield value; }', 'external'):
            with self.subTest(callback=callback):
                self.assert_fill_partial('const items = [req.query.html]; '
                    f'const out = items.flatMap({callback}); res.send(out[0]);', reason='flatMap')
        self.assert_fill_partial('const items = [...unknown]; '
            'const out = items.flatMap(value => [req.query.html]); res.send(out[0]);', reason='flatMap')
        self.assert_fill_partial('res.send(req.query.html); const items = [...unknown]; '
            'const out = items.flatMap(value => ["safe"]); res.send(out[0]);', 'xss', reason='flatMap')

    def test_flatmap_partial_calls_cannot_hide_escaped_callback_sinks(self):
        self.scan('function use(items) { items.flatMap(value => { res.send(req.query.html); return []; }); } '
                  'use([]); use(external);', 'xss')

    def test_flatmap_callback_aliases_in_opaque_arguments_retain_sinks(self):
        for escape in ('external(saved);', 'external(0, saved);',
                       'external(0, {callback: saved});', 'external(0, [saved]);'):
            with self.subTest(escape=escape):
                self.scan('let saved; [].flatMap(saved = () => { '
                          'res.send(req.query.html); return []; }); ' + escape, 'xss')
        self.scan('let saved; [].flatMap(saved = undefined => { '
                  'res.send(req.query.html); return []; }); external(0, saved);', 'xss')
        self.scan('[].flatMap(value => { res.send(req.query.html); return []; }); '
                  'external(0, "safe");')

    def test_flatmap_escaped_callback_observes_later_captured_writes(self):
        source = ('let saved; let html = "safe"; '
                  '[1].flatMap(function expand() { saved = expand; res.send(html); return []; }); '
                  'html = req.query.html; external(0, saved);')
        self.assert_fill_partial(source, 'xss', reason='flatMap.*self-reference')
        self.assert_runtime_sends('function external(ignored, callback) { callback(); } ' + source,
                                  ['safe', 'review-input'])

    def test_flatmap_scalar_literals_are_single_values(self):
        for result in ('"safe"', "'safe'", '`safe`', '42', 'null', 'true', '({html: "safe"})'):
            with self.subTest(result=result):
                self.scan('const items = [req.query.html]; '
                          f'const out = items.flatMap(value => {result}); '
                          'res.send(out[0]); res.send(out[1]);')
        source = ('const items = [req.query.html]; const out = items.flatMap(value => "safe"); '
                  'res.send(out[0]); res.send(out[1]); res.send(out.length);')
        self.assert_runtime_sends(source, ['safe', None, 1])

    def test_flatmap_unproved_result_width_keeps_later_source_positions(self):
        source = ('const flag = false; const items = [1]; '
                  'const out = items.flatMap(value => flag ? [] : "safe"); '
                  'out.push(req.query.html); res.send(out[1]);')
        self.assert_fill_partial(source, 'xss', reason='flatMap.*alternatives')
        self.assert_runtime_sends(source, ['review-input'])
        self.assert_fill_partial('const shared = [req.query.html]; const items = [1]; '
            'const out = items.flatMap(value => shared); res.send(out[0]);',
            'xss', reason='flatMap.*alternatives')
        self.assert_fill_partial('const items = [req.query.html]; '
            'const out = items.flatMap(value => external(value)); res.send(out[0]);',
            'xss', reason='flatMap.*shape')

    def test_flatmap_uncertain_defaults_and_source_lengths_are_explicit(self):
        for initial, expected in (('["safe"]', ['safe']), ('[undefined]', ['review-input'])):
            source = (f'const items = {initial}; '
                      'const out = items.flatMap((value = req.query.html) => [value]); '
                      'res.send(out[0]);')
            with self.subTest(initial=initial):
                self.assert_fill_partial(source, 'xss', reason='flatMap.*default')
                self.assert_runtime_sends(source, expected)
        self.assert_fill_partial('res.send(req.query.html); const items = [1, 2]; '
            'items.flatMap((value, index, source) => { source.length = unknown; return [value]; });',
            'xss', reason='flatMap.*length')

    def test_mixed_scalar_delete_preserves_original_properties(self):
        for scalar in ('0', 'false', '"fixed"'):
            source = ('const box={html:req.query.html,safe:"fixed"}; '
                      f'const target=flag?box:{scalar}; delete target.html; '
                      'res.send(box.html); res.send(box.safe);')
            with self.subTest(scalar=scalar):
                self.scan_sort(source, 'xss')
                self.assert_runtime_sends('const flag=false; ' + source, ['review-input', 'fixed'])
                self.assert_runtime_sends('const flag=true; ' + source, [None, 'fixed'])

    def test_mixed_scalar_length_preserves_original_elements(self):
        for scalar in ('0', 'false', '"fixed"'):
            source = ('const box=[req.query.html,"fixed"]; '
                      f'const target=flag?box:{scalar}; target.length=0; '
                      'res.send(box[0]); res.send(box[1]);')
            with self.subTest(scalar=scalar):
                self.scan_sort(source, 'xss')
                # Primitive writes are ignored in this ordinary, non-strict script.
                self.assert_runtime_sends('const flag=false; ' + source, ['review-input', 'fixed'])
                self.assert_runtime_sends('const flag=true; ' + source, [None, None])

    def test_mixed_scalar_cleanup_preserves_helper_and_stored_aliases(self):
        for initial, mutation, selected in (
            ('{html:req.query.html}', 'delete value.html;', 'box.html'),
            ('[req.query.html]', 'value.length=0;', 'box[0]'),
        ):
            for setup, argument in (
                ('const target=flag?box:0;', 'target'),
                ('const holder={target:flag?box:0};', 'holder.target'),
                ('function select(value){return flag?value:0;}', 'select(box)'),
            ):
                source = (f'function cleanup(value){{{mutation}}} const box={initial}; '
                          + setup + f' cleanup({argument}); res.send({selected});')
                with self.subTest(initial=initial, argument=argument):
                    self.scan_sort(source, 'xss')
                    self.assert_runtime_sends('const flag=false; ' + source, ['review-input'])
                    self.assert_runtime_sends('const flag=true; ' + source, [None])

    def test_mixed_scalar_cleanup_preserves_projection_aliases(self):
        for initial, mutation, member in (
            ('{html:req.query.html}', 'delete target.html;', '.html'),
            ('[req.query.html]', 'target.length=0;', '[0]'),
        ):
            for method, alias in (('values', 'out[0]'), ('entries', 'out[0][1]')):
                source = (f'const box={initial}; const out=Object.{method}({{item:box}}); '
                          f'const target=flag?{alias}:0; {mutation} '
                          f'res.send(box{member}); res.send({alias}{member});')
                with self.subTest(initial=initial, method=method):
                    self.scan_sort(source, 'xss', 'xss')
                    self.assert_runtime_sends('const flag=false; ' + source,
                                              ['review-input', 'review-input'])
                    self.assert_runtime_sends('const flag=true; ' + source, [None, None])

    def test_mixed_scalar_cleanup_keeps_later_projection_limits_explicit(self):
        for initial, mutation, member in (
            ('{html:req.query.html}', 'delete target.html;', '.html'),
            ('[req.query.html]', 'target.length=0;', '[0]'),
        ):
            for method, selected in (('values', 'out[0]'), ('entries', 'out[0][1]')):
                source = (f'const box={initial}; const target=flag?box:0; {mutation} '
                          f'res.send(box{member}); const out=Object.{method}(box); '
                          f'res.send({selected});')
                with self.subTest(initial=initial, method=method):
                    self.scan_sort(source, 'xss', 'xss', partial=f'Object.{method}')
                    self.assert_runtime_sends('const flag=false; ' + source,
                                              ['review-input', 'review-input'])

    def test_exact_cleanup_retains_definite_deletion_and_truncation(self):
        for initial, mutation, member in (
            ('{html:req.query.html}', 'delete target.html;', '.html'),
            ('[req.query.html]', 'target.length=0;', '[0]'),
        ):
            for helper in (False, True):
                action = (f'function cleanup(target){{{mutation}}} cleanup(box);' if helper
                          else f'const target=box; {mutation}')
                source = f'const box={initial}; {action} res.send(box{member});'
                with self.subTest(initial=initial, helper=helper):
                    self.scan_sort(source)
                    self.assert_runtime_sends(source, [None])

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_mixed_scalar_cleanup_public_json_sarif_selection_and_partial(self):
        cases = (
            ('delete', 'const box={html:req.query.html};\nconst target=flag?box:0;\n'
             'delete target.html;\nres.send(box.html);\n',
             [('javascript.taint.xss', 4, 1)], False),
            ('truncate', 'const box=[req.query.html];\nconst target=flag?box:0;\n'
             'target.length=0;\nres.send(box[0]);\n',
             [('javascript.taint.xss', 4, 1)], False),
            ('clean', 'const box={html:req.query.html}; const items=[req.query.html];\n'
             'delete box.html; items.length=0;\nres.send(box.html); res.send(items[0]);\n',
             [], False),
            ('partial', 'const box={html:req.query.html};\nconst target=flag?box:0;\n'
             'delete target.html;\nres.send(box.html);\nconst out=Object.values(box);\n'
             'res.send(out[0]);\n',
             [('javascript.taint.xss', 4, 1), ('javascript.taint.xss', 6, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-mixed-heap-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Object.values')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_mixed_scalar_cleanup_public_cache_edits_exact_suppression_and_partial_nonreuse(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-mixed-heap-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const box=[req.query.html];\nconst target=flag?box:0;\n'
                  'target.length=0;\nres.send(box[0]);\n')
        clean = unsafe.replace('flag?box:0', 'box')
        suppressed = unsafe.replace('res.send(box[0]);',
                                    'res.send(box[0]); // ubs:ignore[javascript.taint.xss]')
        partial = unsafe + 'Object.values(box);\n'
        expected = [('javascript.taint.xss', 4, 1)]
        for index, (source, findings, incomplete, cache_hits) in enumerate((
            (unsafe, expected, False, 0), (unsafe, expected, False, 1), (clean, [], False, 0),
            (suppressed, [], False, 0), (unsafe, expected, False, 1),
            (partial, expected, True, 0), (partial, expected, True, 0),
        )):
            with self.subTest(index=index):
                if index not in (1, 6):
                    target.write_text(source, encoding='utf-8')
                report = self.sort_public_report(target, scratch / f'cache-{index}', meta=True,
                                                fmt='json', expected=findings, partial=incomplete,
                                                cache=True, partial_reason='Object.values')
                self.assertEqual(report['profile']['cache_hits'], cache_hits, report)

    def test_object_keys_returns_fresh_array_of_clean_names(self):
        source = ('const input={10:req.query.html,2:"ok",after:req.query.html}; '
                  'const keys=Object.keys(input); res.send(keys[0]); res.send(keys[1]); '
                  'res.send(keys[2]); res.send(keys.length); '
                  'keys[0]=req.query.html; res.send(keys[0]); res.send(input[2]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['2', '10', 'after', 3, 'review-input', 'ok'])

    def test_object_keys_captured_and_overridden_calls(self):
        source = ('const list=Object.keys; Object.keys=function(input){return [input.value];}; '
                  'const input={value:req.query.html}; '
                  'res.send(list(input)[0]); res.send(Object.keys(input)[0]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['value', 'review-input'])

    def test_object_keys_keeps_unknown_name_provenance_and_partial_findings(self):
        self.scan_sort('const keys=Object.keys(req.body); res.send(keys[0]);', 'xss')
        self.scan_sort('res.send(req.query.html); const box={}; box[req.query.html]="safe"; '
                       'const keys=Object.keys(box);', 'xss', partial='Object.keys')
        self.scan_sort('res.send(req.query.html); delete Object.keys; Object.keys({});',
                       'xss', partial='Object.keys')

    def test_object_keys_checks_each_input_before_returning_clean_names(self):
        for input_expression in ('{dirty:req.query.html}', '[,req.query.html]',
                                 'flag?{a:req.query.html}:{b:"safe"}'):
            self.scan_sort('const flag=true; function names(input){return Object.keys(input);} '
                           f'const keys=names({input_expression}); res.send(keys[0]);')
        self.scan_sort('const Object={keys:function(input){return [input.html];}}; '
                       'res.send(Object.keys({html:req.query.html})[0]);', 'xss')
        self.scan_sort('Object.keys(null); res.send(req.query.html);')

    def test_object_projection_preserves_shallow_values_and_entries(self):
        for expression, selected in (('Object.values({item:box})', 'out[0]'),
                                     ('Object.entries({item:box})', 'out[0][1]')):
            for writer, reader in (('box', selected), (selected, 'box')):
                source = (f'const box={{html:"safe"}}; const out={expression}; '
                          f'{writer}.html=req.query.html; res.send({reader}.html);')
                with self.subTest(expression=expression, writer=writer):
                    self.scan_sort(source, 'xss')
                    self.assert_runtime_sends(source, ['review-input'])

    def test_object_projection_separates_keys_values_and_siblings(self):
        source = ('const input={safe:"fixed",dirty:req.query.html}; '
                  'const values=Object.values(input); const pairs=Object.entries(input); '
                  'res.send(values[0]); res.send(values[1]); res.send(values.length); '
                  'res.send(pairs[0][0]); res.send(pairs[0][1]); '
                  'res.send(pairs[1][0]); res.send(pairs[1][1]);')
        self.scan_sort(source, 'xss', 'xss')
        self.assert_runtime_sends(source, ['fixed', 'review-input', 2, 'safe', 'fixed',
                                           'dirty', 'review-input'])

    def test_object_projection_orders_indices_then_string_insertion(self):
        source = ('const input={10:req.query.html,2:"fixed",z:req.query.html,a:"last"}; '
                  'const out=Object.values(input); res.send(out[0]); res.send(out[1]); '
                  'res.send(out[2]); res.send(out[3]);')
        self.scan_sort(source, 'xss', 'xss')
        self.assert_runtime_sends(source, ['fixed', 'review-input', 'review-input', 'last'])
        source = ('const input={dirty:req.query.html,safe:"fixed"}; '
                  'delete input.dirty; input.dirty=req.query.html; '
                  'const out=Object.values(input); res.send(out[0]); res.send(out[1]);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['fixed', 'review-input'])

    def test_object_projection_own_slots_ignore_holes_and_preserve_named_fields(self):
        source = ('const input=[,"fixed",,req.query.html]; input.extra="last"; '
                  'const out=Object.values(input); res.send(out[0]); res.send(out[1]); '
                  'res.send(out[2]); res.send(out.length);')
        self.scan_sort(source, 'xss')
        self.assert_runtime_sends(source, ['fixed', 'review-input', 'last', 3])
        self.scan_sort('const input=[req.query.html]; input.length=4294967295; '
                       'const out=Object.values(input); res.send(out[0]); res.send(out[1]); '
                       'res.send(out.length);', 'xss')

    def test_object_projection_native_aliases_helpers_and_captured_arguments(self):
        for prefix, expression in (
            ('const project=Object.values;', 'project({item:box})'),
            ('const {values:project}=Object;', 'project({item:box})'),
            ('function project(input){return Object.values(input);}', 'project({item:box})'),
            ('function project(fn,input){return fn(input);}', 'project(Object.values,{item:box})'),
            ('', 'Object["values"]({item:box})'),
        ):
            with self.subTest(prefix=prefix):
                self.scan_sort(prefix + 'const box={html:"safe"}; const out=' + expression
                               + '; box.html=req.query.html; res.send(out[0].html);', 'xss')
        self.scan_sort('function project(input){return Object.entries(input);} '
                       'const out=project({safe:"fixed",dirty:req.query.html}); '
                       'res.send(out[0][1]); res.send(out[1][0]); res.send(out[1][1]);', 'xss')

    def test_object_projection_result_arrays_are_fresh_and_compose_with_callbacks(self):
        self.scan_sort('const input={html:req.query.html}; const out=Object.values(input); '
                       'out[0]="fixed"; res.send(input.html); res.send(out[0]);', 'xss')
        self.scan_sort('const input={html:req.query.html}; const out=Object.entries(input); '
                       'out[0][1]="fixed"; res.send(input.html); res.send(out[0][1]);', 'xss')
        self.scan_sort('const box={html:"safe"}; const out=Object.values({item:box}); '
                       'out.map(item=>{item.html=req.query.html; return "fixed";}); '
                       'res.send(box.html);', 'xss')
        self.scan_sort('const out=Object.entries({html:req.query.html}).map(([key,value])=>key); '
                       'res.send(out[0]);')

    def test_object_projection_strong_updates_and_sink_specific_sanitizers(self):
        self.scan_sort('const box={html:req.query.html}; const out=Object.values({item:box}); '
                       'out[0].html="fixed"; res.send(box.html);')
        self.scan_sort('const out=Object.values({html:DOMPurify.sanitize(req.query.html)}); '
                       'res.send(out[0]); eval(out[0]);', 'eval')
        self.scan_sort('const out=Object.values({html:req.query.html}).map(value=>"fixed"); '
                       'res.send(out[0]);')

    def test_object_projection_shadowed_and_replaced_native_bodies(self):
        self.scan_sort('const Object={values:function(input){return [req.query.html];}}; '
                       'res.send(Object.values({html:"fixed"})[0]);', 'xss')
        self.scan_sort('Object.values=function(input){return ["fixed"];}; '
                       'res.send(Object.values({html:req.query.html})[0]);')
        self.scan_sort('const project=Object.values; Object.values=function(){return [];}; '
                       'const box={html:"safe"}; const out=project({item:box}); '
                       'box.html=req.query.html; res.send(out[0].html);', 'xss')
        self.scan_sort('const box={html:"safe"}; function input(){ '
                       'Object.values=function(){return [];}; return {item:box};} '
                       'const out=Object.values(input()); box.html=req.query.html; '
                       'res.send(out[0].html);', 'xss')

    def test_object_projection_branch_order_and_optional_keys_remain_explicit(self):
        for setup in (
            'const input={}; if(flag){input.a="a";input.b="b";} '
            'else {input.b="b";input.a="a";}',
            'const input={a:"a"}; if(flag){input.b="b";}',
            'const input={a:"a",b:"b"}; if(flag){delete input.a;}',
        ):
            with self.subTest(setup=setup):
                self.scan_sort('res.send(req.query.html); ' + setup + ' Object.values(input);',
                               'xss', partial='Object.values')

    def test_object_projection_protocol_boundaries_keep_prior_findings(self):
        for operation in (
            'Object.values(unknown);',
            'Object.values({get html(){return req.query.html;}});',
            'const input={}; input[key]="fixed"; Object.values(input);',
            'const input={}; Object.defineProperty(input,"html",{get:external}); Object.values(input);',
            'Object.values.call(Object,{html:"fixed"});',
            'delete Object.values; Object.values({html:"fixed"});',
            'Object.values({__proto__:external,html:"fixed"});',
        ):
            with self.subTest(operation=operation):
                self.scan_sort('res.send(req.query.html); ' + operation, 'xss', partial='Object.values')

    def test_object_projection_dynamic_native_members_are_explicit(self):
        for operation in ('const out=Object[key]({item:box});',
                          'const project=Object[key]; const out=project({item:box});'):
            source = ('res.send(req.query.html); const key="values"; const box={html:"safe"}; '
                      + operation + ' box.html=req.query.html; res.send(out[0].html);')
            with self.subTest(operation=operation):
                self.scan_sort(source, 'xss', partial='Object.*projection|Object.*member')
                self.assert_runtime_sends(source, ['review-input', 'review-input'])

    def test_object_projection_nullish_inputs_throw_without_visiting_later_sinks(self):
        for call in ('Object.values(null)', 'Object.entries(undefined)', 'Object.values()',
                     'new Object.values({html:"fixed"})'):
            with self.subTest(call=call):
                self.scan_sort(call + '; res.send(req.query.html);')
                self.scan_sort('try {' + call + ';} catch(error){res.send(req.query.html);}', 'xss')

    def test_object_projection_order_survives_spreads_assignments_and_rest(self):
        for setup in (
            'const input={...{safe:"fixed",dirty:req.query.html}};',
            'const input={}; Object.assign(input,{safe:"fixed",dirty:req.query.html});',
            'const {skip,...input}={skip:0,safe:"fixed",dirty:req.query.html};',
            'function make(){return {safe:"fixed",dirty:req.query.html};} const input=make();',
        ):
            source = setup + 'const out=Object.values(input); res.send(out[0]); res.send(out[1]);'
            with self.subTest(setup=setup):
                self.scan_sort(source, 'xss')
                self.assert_runtime_sends(source, ['fixed', 'review-input'])

    def test_object_projection_joined_objects_and_helper_contexts_stay_distinct(self):
        self.scan_sort('const input=flag?{item:req.query.html}:{item:"fixed"}; '
                       'const out=Object.values(input); res.send(out[0]);', 'xss')
        self.scan_sort('function project(input){return Object.values(input);} '
                       'const dirty=project({item:req.query.html}); const clean=project({item:"fixed"}); '
                       'res.send(dirty[0]); res.send(clean[0]);', 'xss')

    def test_object_projection_scalar_copy_alternatives_cannot_prove_order(self):
        for setup in (
            'const input={...choice,dirty:req.query.html};',
            'const input=Object.assign({},choice,{dirty:req.query.html});',
            'const {skip,...input}=choice; input.dirty=req.query.html;',
        ):
            source = ('res.send(req.query.html); const choice=flag?{safe:"fixed"}:"abcd"; '
                      + setup + ' const out=Object.values(input); res.send(out[4]);')
            with self.subTest(setup=setup):
                self.scan_sort(source, 'xss', 'xss', partial='Object.values')
                self.assert_runtime_sends('const flag=false; ' + source,
                                          ['review-input', 'review-input'])

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_object_projection_public_json_sarif_selection_and_partial(self):
        cases = (
            ('keys', 'const input={dirty:req.query.html};\nconst names=Object.keys(input);\n'
             'res.send(names[0]);\nres.send(input.dirty);\n',
             [('javascript.taint.xss', 4, 1)], False),
            ('alias', 'const box={html:"safe"};\nconst out=Object.values({item:box});\n'
             'box.html=req.query.html;\nres.send(out[0].html);\n',
             [('javascript.taint.xss', 4, 1)], False),
            ('entries', 'const out=Object.entries({html:req.query.html});\nres.send(out[0][0]);\n'
             'res.send(out[0][1]);\n', [('javascript.taint.xss', 3, 1)], False),
            ('clean', 'const out=Object.values({safe:"fixed",dirty:req.query.html});\n'
             'res.send(out[0]);\n', [], False),
            ('partial', 'res.send(req.query.html);\n'
             'Object.values({get html(){return req.query.html;}});\n',
             [('javascript.taint.xss', 1, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-object-projection-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Object.values')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_object_projection_public_cache_edits_suppression_and_partial_nonreuse(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-object-projection-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = ('const box={html:"safe"};\nconst out=Object.values({item:box});\n'
                  'box.html=req.query.html;\nres.send(out[0].html);\n')
        clean = unsafe.replace('box.html=req.query.html;', 'box.html="fixed";')
        suppressed = unsafe.replace('res.send(out[0].html);', 'res.send(out[0].html); // ubs:ignore')
        partial = 'res.send(req.query.html);\nObject.values(unknown);\n'
        expected = [('javascript.taint.xss', 4, 1)]
        for index, (source, findings, incomplete, cache_hits) in enumerate((
            (unsafe, expected, False, 0), (unsafe, expected, False, 1), (clean, [], False, 0),
            (suppressed, [], False, 0), (unsafe, expected, False, 1),
            (partial, [('javascript.taint.xss', 1, 1)], True, 0),
            (partial, [('javascript.taint.xss', 1, 1)], True, 0),
        )):
            with self.subTest(index=index):
                if index not in (1, 6):
                    target.write_text(source, encoding='utf-8')
                report = self.sort_public_report(target, scratch / f'cache-{index}', meta=True,
                                                fmt='json', expected=findings, partial=incomplete,
                                                cache=True, partial_reason='Object.values')
                self.assertEqual(report['profile']['cache_hits'], cache_hits, report)

    def test_array_from_mapper_returns_and_sanitizer_domains(self):
        source = ('const out = Array.from([1], value => req.query.html); '
                  'res.send(out[0]); res.send(out.length);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 1])
        self.scan('const out = Array.from([req.query.html], value => "safe"); '
                  'res.send(out[0]); eval(out[0]); db.query(out[0]); shell.exec(out[0]);')
        self.scan('const out = Array.from([req.query.html], value => DOMPurify.sanitize(value)); '
                  'res.send(out[0]); eval(out[0]); db.query(out[0]); shell.exec(out[0]);',
                  'eval', 'sql', 'command')

    def test_array_from_callback_effects_and_borrowed_objects(self):
        source = ('let saved = "safe"; const box = {html: "safe"}; '
                  'const out = Array.from([box], value => { value.html = req.query.html; '
                  'saved = req.query.html; return value; }); '
                  'res.send(box.html); res.send(out[0].html); res.send(saved);')
        self.scan(source, 'xss', 'xss', 'xss')
        self.assert_runtime_sends(source, ['review-input', 'review-input', 'review-input'])
        self.scan('const box = {html: req.query.html}; '
                  'Array.from([box], value => { value.html = "safe"; return 0; }); res.send(box.html);')
        self.scan('Array.from([req.query.html], value => { res.send(value); return "safe"; });', 'xss')

    def test_array_from_plain_copy_is_fresh_and_shallow(self):
        source = ('const box = {html: "safe"}; const items = [req.query.html, box]; '
                  'const out = Array.from(items); items[0] = "safe"; out[1].html = req.query.html; '
                  'res.send(out[0]); res.send(items[0]); res.send(box.html); res.send(out.length);')
        self.scan(source, 'xss', 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe', 'review-input', 2])
        self.scan('const items = [req.query.html, "safe"]; '
                  'const out = Array.from(items); out[0] = "safe"; '
                  'res.send(items[0]); res.send(out[0]); res.send(out[1]); res.send(out[2]);', 'xss')

    def test_array_from_visits_holes_and_creates_dense_elements(self):
        source = ('const out = Array.from([,], (value = req.query.html) => value); '
                  'res.send(out[0]); res.send(out.length);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 1])
        source = ('const items = Array.from([,]); let saved = "safe"; '
                  'items.map(value => { saved = req.query.html; return value; }); res.send(saved);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan('let saved = "safe"; Array.from([], value => { '
                  'saved = req.query.html; res.send(req.query.html); return value; }); res.send(saved);')

    def test_array_from_uses_live_array_length_and_element_values(self):
        cases = (
            ('const items = ["safe"]; const out = Array.from(items, value => { '
             'items[1] = req.query.html; return value; }); '
             'res.send(out[0]); res.send(out[1]); res.send(out.length);',
             ('xss',), ['safe', 'review-input', 2]),
            ('const items = ["safe", req.query.html]; const out = Array.from(items, value => { '
             'items.length = 1; return value; }); res.send(out[1]); res.send(out.length);',
             (), [None, 1]),
            ('const items = [req.query.html, req.query.html]; const out = Array.from(items, value => { '
             'items[1] = "safe"; return value; }); res.send(out[0]); res.send(out[1]);',
             ('xss',), ['review-input', 'safe']),
        )
        for source, rules, expected in cases:
            with self.subTest(source=source):
                self.scan(source, *rules)
                self.assert_runtime_sends(source, expected)

    def test_array_from_mapper_receives_two_arguments_and_this(self):
        source = ('const out = Array.from(["safe"], function(value, index, missing = req.query.html) { '
                  'return {value, index, missing, html: this.html}; }, {html: req.query.html}); '
                  'res.send(out[0].value); res.send(out[0].index); '
                  'res.send(out[0].missing); res.send(out[0].html);')
        self.scan(source, 'xss', 'xss')
        self.assert_runtime_sends(source, ['safe', 0, 'review-input', 'review-input'])
        self.scan('const out = Array.from([req.query.html], value => "safe", {html: req.query.html}); '
                  'res.send(out[0]);')

    def test_array_from_missing_mapper_parameter_has_proven_undefined_identity(self):
        for expression in ('third === undefined ? "safe" : value',
                           'third !== undefined ? value : "safe"',
                           'undefined === third ? "safe" : value',
                           '(third === undefined) ? "safe" : value'):
            source = ('const out = Array.from([req.query.html], function(value, index, third) { '
                      f'return {expression};' + ' }); res.send(out[0]);')
            with self.subTest(expression=expression):
                self.scan(source)
                self.assert_runtime_sends(source, ['safe'])
        source = ('const out = Array.from([req.query.html], function(value, index, third) { '
                  'if (third === undefined) return "safe"; return value; }); res.send(out[0]);')
        self.scan(source)
        self.assert_runtime_sends(source, ['safe'])
        for setup in ('const undefined = req.query.html;', 'const undefined = "fixed";'):
            source = ('function run() { ' + setup
                      + 'const out = Array.from([req.query.html], function(value, index, third) { '
                      'return third === undefined ? "safe" : value; }); res.send(out[0]); } run();')
            with self.subTest(setup=setup):
                self.scan(source, 'xss')
                self.assert_runtime_sends(source, ['review-input'])
        self.scan('const out = [req.query.html].map(function(value, index, third) { '
                  'return third === undefined ? "safe" : value; }); res.send(out[0]);', 'xss')
        self.scan('const out = Array.from([req.query.html], function(value, index, third = req.query.html) { '
                  'return third === undefined ? "safe" : value; }); res.send(out[0]);', 'xss')
        source = ('function select(value, missing) { return missing === undefined ? "safe" : value; } '
                  'res.send(select(req.query.html)); res.send(select(req.query.html, null));')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['safe', 'review-input'])

    def test_array_from_native_aliases_and_optional_mapper(self):
        for setup, call in (
                ('const Native = Array;', 'Native.from'),
                ('const copy = Array.from;', 'copy'),
                ('const {from: copy} = Array;', 'copy'),
                ('const operations = {copy: Array.from};', 'operations.copy'),
                ('function factory() { return Array.from; } const copy = factory();', 'copy')):
            for extra in ('', ', undefined', ', void 0'):
                with self.subTest(setup=setup, extra=extra):
                    self.scan(setup + f'const out = {call}([req.query.html, "safe"]{extra}); '
                              'res.send(out[0]); res.send(out[1]); res.send(out.length);', 'xss')
        self.scan('const copy = Array.from; Array.from = external; '
                  'const out = copy([1], value => req.query.html); res.send(out[0]);', 'xss')

    def test_array_from_captures_callee_and_mapper_before_later_arguments(self):
        source = ('const items = ["safe"]; let map = value => value; '
                  'const out = Array.from(items, map, (map = () => "safe", items[0] = req.query.html)); '
                  'res.send(out[0]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        self.scan('const out = Array.from([1], value => req.query.html, Array.from = external); '
                  'res.send(out[0]);', 'xss')

    def test_array_from_selected_helpers_keep_context_and_module_locations(self):
        source = ('function map(value) { return {html: value}; } '
                  'function copy(items, mapper) { return Array.from(items, mapper); } '
                  'const dirty = copy([req.query.html], map); const clean = copy(["safe"], map); '
                  'res.send(dirty[0].html); res.send(clean[0].html);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input', 'safe'])
        artifacts = ROOT / 'test-suite/artifacts/javascript-array-from'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='modules-', dir=artifacts))
        helper, entry = scratch / 'copy.mjs', scratch / 'handler.mjs'
        helper.write_text('export function copy(items) { return Array.from(items, value => ({html: value})); }\n',
                          encoding='utf-8')
        entry.write_text('import {copy} from "./copy.mjs";\nconst out = copy([req.query.html]);\n'
                         'res.send(out[0].html);\n', encoding='utf-8')
        findings = list(taint.run(RunContext(lang='javascript', files=[entry, helper])))
        self.assertEqual([(f['rule'], f['path'], f['line']) for f in findings],
                         [('javascript.taint.xss', str(entry), 3)])

    def test_array_from_shadowed_or_replaced_functions_use_selected_bodies(self):
        for setup in ('const Array = {from(items, mapper) { return ["safe"]; }};',
                      'Array.from = function(items, mapper) { return ["safe"]; };'):
            with self.subTest(setup=setup):
                self.scan(setup + 'const out = Array.from([req.query.html], value => req.query.html); '
                          'res.send(out[0]);')
        self.scan('const Array = {from(items, mapper) { return [req.query.html]; }}; '
                  'const out = Array.from(["safe"], value => "safe"); res.send(out[0]);', 'xss')
        self.scan('function copy(Array) { return Array.from([req.query.html]); } '
                  'res.send(copy({from() { return ["safe"]; }})[0]);')

    def test_array_from_exceptions_keep_effects_and_skip_later_work(self):
        source = ('let saved = "safe"; try { Array.from([req.query.html], value => { '
                  'saved = value; throw "stop"; }); saved = "safe"; '
                  '} catch (error) { res.send(saved); }')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        source = ('try { Array.from([req.query.html], value => { throw value; }); '
                  'res.send(req.query.html); } catch (error) { res.send(error); }')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])

    def test_array_from_unknown_inputs_and_mapper_protocols_stay_partial(self):
        for expression in ('opaque', '{0: req.query.html, length: 1}',
                           'new Set([req.query.html])', 'flag ? [req.query.html] : "safe"'):
            with self.subTest(expression=expression):
                self.assert_fill_partial('res.send(req.query.html); '
                    f'const out = Array.from({expression}, value => "safe");', 'xss', reason='Array.from')
        for callback in ('external', 'async value => value', 'function*(value) { yield value; }'):
            with self.subTest(callback=callback):
                self.assert_fill_partial('res.send(req.query.html); '
                    f'const out = Array.from(["safe"], {callback});', 'xss', reason='Array.from')
        self.assert_fill_partial('res.send(req.query.html); const items = ["safe"]; '
            'Array.from(items, value => { items.length = unknown; return value; });',
            'xss', reason='Array.from.*length')

    def test_array_from_custom_iteration_and_factory_protocols_stay_partial(self):
        for setup in ('items[Symbol.iterator] = external;',
                      'Array.prototype[Symbol.iterator] = external;',
                      'Object.defineProperty(items, "0", {get() { return req.query.html; }});',
                      'external(items);'):
            with self.subTest(setup=setup):
                self.assert_fill_partial('res.send(req.query.html); const items = ["safe"]; '
                    + setup + ' Array.from(items, value => "safe");', 'xss', reason='Array.from')
        for call in ('Array.from.call(external, ["safe"]);',
                     'Array.from = external; Array.from(["safe"]);'):
            with self.subTest(call=call):
                self.assert_fill_partial('res.send(req.query.html); ' + call, 'xss', reason='Array.from')

    def test_array_from_sparse_traversal_respects_work_limit(self):
        self.assert_fill_partial('res.send(req.query.html); const items = []; items.length = 4294967294; '
            'Array.from(items, value => "safe");', 'xss', reason='Array.from.*work limit')

    def test_array_from_mixed_mapper_cannot_prove_unconditional_cleanup(self):
        for mapper in ('flag ? clear : undefined', 'flag ? undefined : clear',
                       'flag ? clear : external', 'flag ? clear : null'):
            source = ('const box = {html: req.query.html}; '
                      'function clear(value) { box.html = "safe"; return "safe"; } '
                      f'const mapper = {mapper}; '
                      'res.send(req.query.html); const out = Array.from([req.query.html], mapper); '
                      'res.send(box.html);')
            with self.subTest(mapper=mapper):
                self.assert_fill_partial(source, 'xss', 'xss', reason='Array.from.*mapper')
        source = ('const box = {html: req.query.html}; '
                  'function clear(value) { box.html = "safe"; return "safe"; } '
                  'const mapper = flag ? clear : undefined; '
                  'const out = Array.from([req.query.html], mapper); '
                  'res.send(box.html); res.send(out[0]);')
        self.assert_runtime_sends('const flag = false; ' + source, ['review-input', 'review-input'])
        self.assert_runtime_sends('const flag = true; ' + source, ['safe', 'safe'])

    def test_array_from_invalid_mappers_and_missing_sources_throw_before_iteration(self):
        for expression in ('Array.from()', 'Array.from(null)', 'Array.from(undefined)',
                           'Array.from([req.query.html], null)', 'Array.from([req.query.html], 1)',
                           'Array.from([req.query.html], false)', 'new Array.from([req.query.html])'):
            source = ('let saved = "safe"; try { ' + expression + '; saved = req.query.html; '
                      '} catch (error) {} res.send(saved);')
            with self.subTest(expression=expression):
                self.scan(source)
                self.assert_runtime_sends(source, ['safe'])

    def test_array_from_argument_evaluation_cannot_reuse_an_earlier_mapper_binding(self):
        source = ('const box = {html: req.query.html}; '
                  'let mapper = value => { box.html = "safe"; return "safe"; }; '
                  'function inputs() { mapper = external; return [req.query.html]; } '
                  'res.send(req.query.html); const out = Array.from(inputs(), mapper); '
                  'res.send(box.html);')
        self.assert_fill_partial(source, 'xss', 'xss', reason='Array.from.*mapper')
        source = ('let mapper = value => "safe"; '
                  'function inputs() { mapper = undefined; return [req.query.html]; } '
                  'const out = Array.from(inputs(), mapper); res.send(out[0]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])

    def test_array_from_uncertain_this_argument_cannot_clean_a_possible_receiver(self):
        source = ('const box = {html: req.query.html}; const receiver = flag ? box : undefined; '
                  'res.send(req.query.html); Array.from([1], function(value) { this.html = "safe"; }, receiver); '
                  'res.send(box.html);')
        self.assert_fill_partial(source, 'xss', 'xss', reason='Array.from.*this')
        self.assert_runtime_sends('const flag = false; ' + source, ['review-input', 'review-input'])
        self.assert_runtime_sends('const flag = true; ' + source, ['review-input', 'safe'])

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real module and meta-runner integration requires ast-grep')
    def test_array_from_public_json_sarif_selection_and_partial(self):
        cases = (
            ('mapped-source', 'const out=Array.from([1],value=>req.query.html);\n'
             'res.send(out[0]);\nres.send(out.length);\n',
             [('javascript.taint.xss', 2, 1)], False),
            ('mapped-clean', 'const out=Array.from([req.query.html],value=>"safe");\n'
             'res.send(out[0]);\n', [], False),
            ('borrowed-object', 'const box={html:"safe"};\nconst out=Array.from([box]);\n'
             'box.html=req.query.html;\nres.send(out[0].html);\n',
             [('javascript.taint.xss', 4, 1)], False),
            ('partial-iterator', 'res.send(req.query.html);\nconst items=["safe"];\n'
             'items[Symbol.iterator]=external;\nArray.from(items);\n',
             [('javascript.taint.xss', 1, 1)], True),
            ('partial-mapper', 'res.send(req.query.html);\nconst box={html:req.query.html};\n'
             'function clear(value){box.html="safe";return "safe";}\n'
             'const mapper=flag?clear:undefined;\nArray.from([1],mapper);\nres.send(box.html);\n',
             [('javascript.taint.xss', 1, 1), ('javascript.taint.xss', 6, 1)], True),
        )
        artifacts = ROOT / 'test-suite/artifacts/javascript-array-from-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='formats-', dir=artifacts))
        for name, source, expected, partial in cases:
            project = scratch / name
            project.mkdir()
            target = project / 'handler.js'
            target.write_text(source, encoding='utf-8')
            (project / 'unselected.js').write_text('res.send(req.query.html);\n', encoding='utf-8')
            for meta, fmt in itertools.product((False, True), ('json', 'sarif')):
                with self.subTest(case=name, meta=meta, format=fmt):
                    self.sort_public_report(target, project / f'{meta}-{fmt}', meta=meta, fmt=fmt,
                                            expected=expected, partial=partial, partial_reason='Array.from')

    @unittest.skipUnless(shutil.which('ast-grep') or os.environ.get('UBS_AST_GREP_BIN'),
                         'real meta-runner cache integration requires ast-grep')
    def test_array_from_public_cache_edits_suppression_and_partial_nonreuse(self):
        artifacts = ROOT / 'test-suite/artifacts/javascript-array-from-public'
        artifacts.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix='cache-', dir=artifacts))
        target = scratch / 'handler.js'
        unsafe = 'const out=Array.from([1],value=>req.query.html);\nres.send(out[0]);\n'
        clean = 'const out=Array.from([req.query.html],value=>"safe");\nres.send(out[0]);\n'
        suppressed = unsafe.replace('res.send(out[0]);', 'res.send(out[0]); // ubs:ignore')
        partial = 'res.send(req.query.html);\nArray.from(unknown,value=>"safe");\n'
        cases = (
            (unsafe, [('javascript.taint.xss', 2, 1)], False, 0),
            (unsafe, [('javascript.taint.xss', 2, 1)], False, 1),
            (clean, [], False, 0), (suppressed, [], False, 0),
            (unsafe, [('javascript.taint.xss', 2, 1)], False, 1),
            (partial, [('javascript.taint.xss', 1, 1)], True, 0),
            (partial, [('javascript.taint.xss', 1, 1)], True, 0),
        )
        for index, (source, expected, incomplete, cache_hits) in enumerate(cases):
            with self.subTest(index=index):
                if index not in (1, 6):
                    target.write_text(source, encoding='utf-8')
                report = self.sort_public_report(target, scratch / f'cache-{index}', meta=True, fmt='json',
                                                expected=expected, cache=True, partial=incomplete,
                                                partial_reason='Array.from')
                self.assertEqual(report['profile']['cache_hits'], cache_hits, report)

    def assert_fill_partial(self, source, *rules, reason='Array.fill'):
        with temporary_directory(prefix='ubs-fill-partial-') as scratch:
            path = Path(scratch) / 'handler.js'
            path.write_text(source + '\n', encoding='utf-8')
            findings = []
            with self.assertRaisesRegex(taint.AnalysisLimit, reason):
                findings.extend(taint.run(RunContext(lang='javascript', files=[path])))
        self.assertEqual(Counter(f['rule'].removeprefix('javascript.taint.') for f in findings),
                         Counter(rules), (source, findings))

    def test_fill_opaque_bounds_keep_evidence_and_report_incomplete(self):
        self.assert_fill_partial('const items = [req.query.html]; '
                                 'items.fill("safe", offset); res.send(items[0]);', 'xss')
        self.assert_fill_partial('const items = ["safe"]; '
                                 'items.fill("safe", req.query.offset); res.send(items[0]);')
        self.assert_fill_partial('const undefined = external; const items = [req.query.html]; '
                                 'items.fill("safe", 0, undefined); res.send(items[0]);', 'xss')
        self.assert_fill_partial('const source = req.query.html; const items = []; '
                                 'items.fill(source, {valueOf: external}); res.send(items[0]);')
        self.assert_fill_partial('const items = ["safe"]; '
                                 'items.fill(...req.query.values); res.send(items[0]);', 'xss')
        self.assert_fill_partial('const items = [req.query.html]; '
                                 'try { items.fill("safe", 1n); } catch (error) {} '
                                 'res.send(items[0]);', 'xss')

    def test_fill_nonstandard_write_contract_cannot_certify_cleanup(self):
        for setup in ('Object.freeze(items);', 'Object.seal(items);',
                      'Object.preventExtensions(items);',
                      'Object.defineProperty(items, "0", {value: "locked"});',
                      'Object.defineProperties(items, {0: {value: "locked"}});',
                      'Reflect.defineProperty(items, "0", {value: "locked"});',
                      'Object.defineProperty(items, ...req.query.options);',
                      'Object.defineProperty(items, "note", {get value() { Object.freeze(items); return 0; }});',
                      'external({items});'):
            with self.subTest(setup=setup):
                self.assert_fill_partial('const items = [,req.query.html]; ' + setup
                                         + 'try { items.fill("safe"); } catch (error) {} '
                                         'res.send(items[1]);', 'xss')

    def test_fill_fresh_copies_do_not_inherit_descriptor_metadata(self):
        for copy in ('const copied = [...items];',
                     'const copied = Object.assign([], items);',
                     'const copy = {...items}; const copied = Object.assign([], copy);',
                     'const {...copy} = items; const copied = Object.assign([], copy);'):
            with self.subTest(copy=copy):
                self.scan('const items = [req.query.html]; Object.freeze(items); ' + copy
                          + 'copied.fill("safe"); res.send(copied[0]);')
        self.scan('const items = [req.query.html]; Object.freeze({items}); '
                  'items.fill("safe"); res.send(items[0]);')

    def test_fill_descriptor_getters_preserve_nested_and_captured_evidence(self):
        descriptor = ('{get value() { Object.defineProperty(box.items, "0", '
                      '{set(value) {}, get() { return req.query.html; }}); return "note"; }}')
        for call in ('Object.defineProperty(box, "note", ' + descriptor + ')',
                     'Reflect.defineProperty(box, "note", ' + descriptor + ')',
                     'Object.defineProperties(box, {note: ' + descriptor + '})'):
            with self.subTest(call=call):
                source = ('const box = {items: [req.query.html]}; const inner = box.items; '
                          + call + '; inner.fill("safe"); '
                          'res.send(box.items[0]); res.send(inner[0]);')
                self.assert_runtime_sends(source, ['review-input', 'review-input'])
                self.assert_fill_partial(source, 'xss', 'xss')
        source = ('const items = [req.query.html]; Object.defineProperties({}, {note: {get value() { '
                  'Object.defineProperty(items, "0", {set(value) {}, get() {return req.query.html;}}); '
                  'return "note"; }}}); items.fill("safe"); res.send(items[0]);')
        self.assert_runtime_sends(source, ['review-input'])
        self.assert_fill_partial(source, 'xss')

    def test_fill_descriptor_values_and_property_keys_keep_opaque_effects(self):
        calls = (
            'const descriptor = {extra: items, get value() { '
            'Object.defineProperty(this.extra, "0", {set(value) {}, get() {return req.query.html;}}); '
            'return "note"; }}; Object.defineProperty({}, "note", descriptor);',
            'const key = {toString() { Object.freeze(items); return "note"; }}; '
            'Object.defineProperty({}, key, {value: "note"});',
            'const other = []; Object.defineProperty(other, "length", '
            '{value: {valueOf() {Object.freeze(items); return 0;}}});',
        )
        for call in calls:
            with self.subTest(call=call):
                source = ('const items = [req.query.html]; ' + call
                          + ' try {items.fill("safe");} catch (error) {} res.send(items[0]);')
                self.assert_runtime_sends(source, ['review-input'])
                self.assert_fill_partial(source, 'xss')

    def test_fill_descriptor_effects_survive_local_summaries(self):
        source = ('function protect(box) { Object.defineProperties({}, {note: {get value() { '
                  'Object.freeze(box.items); return "note"; }}}); } '
                  'const box = {items: [req.query.html]}; protect(box); '
                  'try {box.items.fill("safe");} catch (error) {} res.send(box.items[0]);')
        self.assert_runtime_sends(source, ['review-input'])
        self.assert_fill_partial(source, 'xss')

    def test_fill_assign_getters_and_proxy_targets_remain_partial(self):
        calls = (
            'Object.assign({}, {get note() {Object.freeze(items); return "note";}});',
            'Object.assign({set note(value) {Object.freeze(items);}}, {note: "note"});',
            'const target = new Proxy({}, {defineProperty() {Object.freeze(items); return true;}}); '
            'Object.defineProperty(target, "note", {value: "note", configurable: true});',
            'const target = new Proxy({}, {set() {Object.freeze(items); return true;}}); '
            'Object.assign(target, {note: "note"});',
        )
        for call in calls:
            with self.subTest(call=call):
                source = ('const items = [req.query.html]; ' + call
                          + ' try {items.fill("safe");} catch (error) {} res.send(items[0]);')
                self.assert_runtime_sends(source, ['review-input'])
                self.assert_fill_partial(source, 'xss')

    def test_fill_plain_data_descriptors_and_readonly_copies_stay_clean(self):
        for call in ('Object.defineProperty(exports, "__esModule", {value: true});',
                     'Reflect.defineProperty(exports, "__esModule", {value: true});',
                     'Object.defineProperties(exports, {__esModule: {value: true}});',
                     'Object.defineProperty(exports, "__esModule", {value: true}); '
                     'Object.defineProperty(exports, "answer", {value: 42});'):
            with self.subTest(call=call):
                source = ('const exports = {}; ' + call + ' const items = [req.query.html]; '
                          'items.fill("safe"); res.send(items[0]);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan(source)
        for copy in ('const copied = [...items];', 'const copied = Object.assign([], items);',
                     'const copy = {...items}; const copied = Object.assign([], copy);'):
            with self.subTest(copy=copy):
                source = ('const items = [req.query.html]; '
                          'Object.defineProperty(items, "0", {value: req.query.html, writable: false}); '
                          + copy + ' copied.fill("safe"); res.send(copied[0]);')
                self.assert_runtime_sends(source, ['safe'])
                self.scan(source)

    def test_fill_commonjs_export_flags_do_not_poison_later_arrays(self):
        source = ('Object.defineProperty(exports, "__esModule", {value: true}); '
                  'const items = [req.query.html]; items.fill("safe"); res.send(items[0]);')
        self.assert_runtime_sends('const exports = {}; ' + source, ['safe'])
        with tempfile.TemporaryDirectory(prefix='ubs-fill-commonjs-') as scratch:
            path = Path(scratch) / 'handler.cjs'
            path.write_text(source + '\n', encoding='utf-8')
            self.assertEqual(list(taint.run(RunContext(lang='javascript', files=[path]))), [])
            for setup in (
                'exports = new Proxy({}, {defineProperty() {Object.freeze(items); return true;}}); '
                'Object.defineProperty(exports, "flag", {value: true, configurable: true});',
                'function install(exports) { '
                'Object.defineProperty(exports, "flag", {value: true, configurable: true}); } '
                'install(new Proxy({}, {defineProperty() {Object.freeze(items); return true;}}));',
            ):
                with self.subTest(setup=setup):
                    source = ('const items = [req.query.html]; ' + setup
                              + ' try {items.fill("safe");} catch (error) {} res.send(items[0]);')
                    self.assert_runtime_sends('let exports = {}; ' + source, ['review-input'])
                    path.write_text(source + '\n', encoding='utf-8')
                    findings = []
                    with self.assertRaisesRegex(taint.AnalysisLimit, 'Array.fill'):
                        findings.extend(taint.run(RunContext(lang='javascript', files=[path])))
                    self.assertEqual([row['rule'] for row in findings], ['javascript.taint.xss'])

    def test_array_restriction_results_keep_returned_aliases(self):
        for expression in ('Object.preventExtensions(items)', 'Object.seal(items)',
                           'Object.defineProperties(items, {})',
                           'Object.setPrototypeOf(items, Array.prototype)',
                           'Object.defineProperty(items, ...opaqueOptions)'):
            with self.subTest(expression=expression):
                self.assert_fill_partial('const items = ["safe"]; '
                    f'const alias = {expression}; '
                    'alias.fill(req.query.html); res.send(items[0]);', 'xss',
                    reason='Array.fill|Object[.]')
        self.assert_fill_partial('const items = [req.query.html]; '
            'const alias = Object.freeze(items); '
            'try { alias.fill("safe"); } catch (error) {} res.send(items[0]);', 'xss')

    def test_array_descriptor_returns_retain_prior_provenance(self):
        for expression, reason in (
                ('Object.defineProperties(items, {0: {value: req.query.html}})', 'Object[.]defineProperties'),
                ('Object.setPrototypeOf(items, {0: req.query.html})', 'Object[.]setPrototypeOf')):
            with self.subTest(expression=expression):
                self.assert_fill_partial('const items = []; items.length = 1; '
                    f'const alias = {expression}; res.send(alias[0]);', 'xss', reason=reason)
        # Nonarray callers retain the existing conservative descriptor result.
        self.scan('const result = Object.defineProperties({}, {html: {value: req.query.html}}); '
                  'res.send(result.html);', 'xss')

    def test_array_reflect_results_are_booleans(self):
        self.scan('const items = [req.query.html]; '
                  'const result = Reflect.preventExtensions(items); res.send(result);')
        for expression, reason in (
                ('Reflect.defineProperty(items, "0", {value: req.query.html})', 'Reflect[.]defineProperty'),
                ('Reflect.setPrototypeOf(items, {0: req.query.html})', 'Reflect[.]setPrototypeOf')):
            with self.subTest(expression=expression):
                self.assert_fill_partial('const items = []; '
                    f'const result = {expression}; res.send(result);', reason=reason)

    def test_array_restriction_mixed_targets_cannot_report_complete_cleanup(self):
        self.assert_fill_partial('const items = [req.query.html]; '
            'let target = items; if (flag) target = {}; '
            'const alias = Object.preventExtensions(target); '
            'try { alias.fill("safe"); } catch (error) {} res.send(items[0]);',
            'xss', reason='Object[.]preventExtensions')

    def test_fill_large_extent_obeys_work_budget(self):
        with tempfile.TemporaryDirectory(prefix='ubs-fill-budget-') as scratch:
            path = Path(scratch) / 'handler.js'
            path.write_text('const items = []; items.length = 4294967295; '
                            'items.fill(req.query.html); res.send(items[0]);\n', encoding='utf-8')
            with self.assertRaises(taint.AnalysisLimit):
                list(taint.run(RunContext(lang='javascript', files=[path])))

    def test_own_function_method_mutates_captured_receiver(self):
        source = ('const items = ["safe"];\n'
                  'items.fill = function(value) { this[0] = req.query.html; return this; };\n'
                  'const alias = items.fill("clean");\n'
                  'res.send(items[0]);\nres.send(alias[0]);')
        findings = self.scan(source, 'xss', 'xss')
        self.assertEqual([finding['line'] for finding in findings], [4, 5])
        self.assert_runtime_sends(source, ['review-input', 'review-input'])

    def test_own_shorthand_method_uses_body_return(self):
        source = ('const object = {fill(value) { return "clean"; }};\n'
                  'res.send(object.fill(req.query.html));')
        self.scan(source)
        self.assert_runtime_sends(source, ['clean'])
        self.scan('const object = {fill(value) { return value; }}; '
                  'res.send(object.fill(req.query.html));', 'xss')

    def test_own_method_borrowing_binds_call_site_receiver(self):
        source = ('const first = {html: "safe", put(value) { this.html = value; return this; }};\n'
                  'const second = {html: "other", put: first.put};\n'
                  'const returned = second.put(req.query.html);\n'
                  'res.send(first.html);\nres.send(second.html);\nres.send(returned.html);')
        findings = self.scan(source, 'xss', 'xss')
        self.assertEqual([finding['line'] for finding in findings], [5, 6])
        self.assert_runtime_sends(source, ['safe', 'review-input', 'review-input'])

    def test_own_method_captures_receiver_and_callee_before_arguments(self):
        source = ('let object = {html: "old", put(value) { this.html = value; return this; }};\n'
                  'const old = object;\n'
                  'const returned = object.put((object = {html: "new"}, req.query.html));\n'
                  'res.send(old.html);\nres.send(object.html);\nres.send(returned.html);')
        findings = self.scan(source, 'xss', 'xss')
        self.assertEqual([finding['line'] for finding in findings], [4, 6])
        self.assert_runtime_sends(source, ['review-input', 'new', 'review-input'])
        self.scan('const object = {html: "safe", put(value) { this.html = value; }}; '
                  'object.put((object.put = function() {}, req.query.html)); res.send(object.html);', 'xss')

    def test_own_literal_computed_method_and_delete(self):
        source = ('const box = {html: "safe", run(value) { this.html = value; }};\n'
                  'box["run"](req.query.html);\nres.send(box.html);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        source = ('const box = {html: "safe", run() { this.html = req.query.html; }};\n'
                  'delete box.run;\ntry { box.run(); } catch (error) {}\nres.send(box.html);')
        self.scan(source)
        self.assert_runtime_sends(source, ['safe'])
        source = ('const items = ["safe"]; items.fill = function() { return this; };\n'
                  'delete items.fill; items.fill(req.query.html); res.send(items[0]);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])
        source = ('const box = {html: "safe", run(value) { this.html = value; }};\n'
                  'box.run((delete box.run, req.query.html));\nres.send(box.html);')
        self.scan(source, 'xss')
        self.assert_runtime_sends(source, ['review-input'])

    def test_own_method_defaults_observe_captured_this(self):
        self.scan('const box = {html: req.query.html, read(value=this.html) { return value; }}; '
                  'res.send(box.read());', 'xss')
        self.scan('const box = {html: req.query.html, read(value=this.html) { return value; }}; '
                  'res.send(box.read("clean"));')
        source = ('const box = {html: "safe", run(value=(this.html=req.query.html,"clean")) { return value; }};\n'
                  'res.send(box.run());\nres.send(box.html);')
        findings = self.scan(source, 'xss')
        self.assertEqual([finding['line'] for finding in findings], [3])
        self.assert_runtime_sends(source, ['clean', 'review-input'])

    def test_own_method_unknown_and_descriptor_paths_stay_partial(self):
        for setup in ('external(box);', 'Object.freeze(box);',
                      'box.run = flag ? box.run : external;'):
            with self.subTest(setup=setup):
                self.assert_fill_partial('const box = {html:req.query.html, run(){this.html="clean";}}; '
                                         + setup + ' try { box.run(); } catch(error) {} res.send(box.html);',
                                         'xss', reason='Own method')
        self.assert_fill_partial('const box={html:"clean",get run(){return function(){this.html=req.query.html;}}}; '
                                 'box.run(); res.send(box.html);', reason='Own method')

    def test_own_method_unknown_replacement_retains_callable_boundary(self):
        for returned in ('req.query.html', '"clean"'):
            with self.subTest(returned=returned):
                self.assert_fill_partial('const supplied=req.query.html; const box={run(){return "clean";}}; '
                    'box.run=Reflect.get({run:function(){return ' + returned + ';}},"run"); '
                    'res.send(box.run());', reason='Own method|Callable')

    def test_own_method_unknown_computed_selection_keeps_possible_absence(self):
        for initial, returned, observed, rules in (
                ('req.query.html', '"clean"', 'review-input', ('xss',)),
                ('"safe"', 'req.query.html', 'safe', ())):
            for call in ('html=box[key]();', 'const read=box[key]; html=read();'):
                with self.subTest(initial=initial, call=call):
                    source = ('let html=' + initial + '; const box={run(){return ' + returned + ';}}; '
                              'const key="missing"; try {' + call + '} catch(error) {} res.send(html);')
                    self.assert_runtime_sends(source, [observed])
                    self.assert_fill_partial(source, *rules, reason='Own method|Callable')

    def test_own_method_unbound_and_escaped_receivers_remain_partial(self):
        self.assert_fill_partial('const box={html:req.query.html,read(){return this.html;}}; '
                                 'const read=box.read; try { res.send(read()); } catch(error) {}',
                                 reason='receiver')
        self.assert_fill_partial('function make(value){return {read(){return value;}};} '
                                 'const dirty=make(req.query.html); const clean=make("clean"); '
                                 'res.send(dirty.read()); res.send(clean.read());', reason='closure')
        self.assert_fill_partial('const box={html:"clean",read:()=>this.html}; '
                                 'this.html=req.query.html; res.send(box.read());', reason='lexical receiver')

    def test_own_method_delete_does_not_erase_prototype_evidence(self):
        self.assert_fill_partial('const items=[req.query.html]; '
                                 'items.__proto__={fill(){return this;}}; delete items.__proto__; '
                                 'items.fill("clean"); res.send(items[0]);', 'xss', reason='Array.fill')
        source = ('const items=[req.query.html]; items.extra={fill(){return this;}}; '
                  'delete items.extra; items.fill("clean"); res.send(items[0]);')
        self.scan(source)
        self.assert_runtime_sends(source, ['clean'])

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
            ('fill-source', 'const a=["safe"]; const b=a; b.fill(req.query.code); eval(a[0]);', {'eval'}),
            ('fill-clean', 'const a=[req.query.html]; a.fill("safe"); res.send(a[0]);', set()),
            ('fill-range', 'const a=["safe", "safe"]; a.fill(req.query.html, 1); res.send(a[0]);', set()),
            ('fill-length', 'const a=["safe"]; res.send(a.fill(req.query.html).length);', set()),
            ('fill-shared-value', 'const box={html:"safe"}; const a=[null,null]; a.fill(box); a[0].html=req.query.html; res.send(a[1].html);', {'xss'}),
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
            ('global-undefined-write-keeps-default', 'function read(value=req.query.html){return value;} undefined="safe"; res.send(read(undefined));', {'xss'}),
            ('nested-global-undefined-write-keeps-default', 'function read(value=req.query.html){return value;} function outer(){undefined="safe";return read(undefined);} res.send(outer());', {'xss'}),
            ('local-undefined-write-bypasses-default', 'function read(value=req.query.html){return value;} function outer(){let undefined;undefined="safe";return read(undefined);} res.send(outer());', set()),
            ('strict-undefined-write-skips-cleanup', '"use strict";const box={html:req.query.html};try{undefined="safe";box.html="safe";}catch(error){}res.send(box.html);', {'xss'}),
            ('strict-undefined-write-keeps-rhs-cleanup', '"use strict";const box={html:req.query.html};try{undefined=(box.html="safe");box.html=req.query.html;}catch(error){}res.send(box.html);', set()),
            ('strict-undefined-and-bypasses-write', '"use strict";const box={html:req.query.html};undefined&&=(box.html="safe");res.send(box.html);', {'xss'}),
            ('strict-undefined-or-keeps-rhs-source', '"use strict";const box={html:"safe"};try{undefined||=(box.html=req.query.html);box.html="safe";}catch(error){}res.send(box.html);', {'xss'}),
            ('strict-undefined-catch-repairs-store', '"use strict";const box={html:req.query.html};try{undefined="safe";}catch(error){box.html="safe";}res.send(box.html);', set()),
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



class BorrowedArrayFillTests(unittest.TestCase):
    def scan_file(self, body: str):
        from ubs_core.analyzers import taint_js
        with tempfile.TemporaryDirectory(prefix='ubs-js-borrowed-fill-') as tmp:
            path = Path(tmp) / 'case.js'
            path.write_text('function handler(req, res, obj) {\n' + body + '\n}\n', encoding='utf-8')
            return list(taint_js.scan_file_findings(path))

    def test_borrowed_array_fill_call_matches_node_runtime_witness(self):
        cases = [
            ('proto-fill-call-unsafe', True,
             'const a = ["safe"]; Array.prototype.fill.call(a, req.query.html); res.send(a[0]);'),
            ('proto-fill-call-range-hit', True,
             'const a = ["safe", "safe"]; Array.prototype.fill.call(a, req.query.html, 1, 2); res.send(a[1]);'),
            ('proto-fill-call-range-miss', False,
             'const a = ["safe", "safe"]; Array.prototype.fill.call(a, req.query.html, 1, 2); res.send(a[0]);'),
            ('proto-fill-call-clean-overwrite', False,
             'const a = [req.query.html, "safe"]; Array.prototype.fill.call(a, "clean", 0, 1); res.send(a[0]);'),
            ('saved-proto-fill-call-unsafe', True,
             'const a = ["safe"]; const fn = Array.prototype.fill; fn.call(a, req.query.html); res.send(a[0]);'),
            ('borrowed-instance-fill-call-unsafe', True,
             'const a = ["safe"]; const b = ["x"]; const fn = b.fill; fn.call(a, req.query.html); res.send(a[0]);'),
            ('literal-empty-fill-call-unsafe', True,
             'const a = ["safe"]; [].fill.call(a, req.query.html); res.send(a[0]);'),
            ('literal-array-direct-fill-unsafe', True,
             'res.send(["safe"].fill(req.query.html)[0]);'),
        ]
        prefix = (
            'const req = {query:{html:"<UNTRUSTED>"}}; const outputs = []; '
            'const res = {send: value => outputs.push(value)}; '
        )
        node_bin = shutil.which('node')
        for name, expected_unsafe, body in cases:
            with self.subTest(case=name):
                if node_bin is not None:
                    node = subprocess.run(
                        [node_bin, '-e', prefix + body + ' console.log(JSON.stringify(outputs));'],
                        capture_output=True, text=True, timeout=15,
                    )
                    self.assertEqual(node.returncode, 0, node.stdout + node.stderr)
                    self.assertEqual('<UNTRUSTED>' in node.stdout, expected_unsafe, (name, node.stdout))
                findings = self.scan_file(body)
                rules = [f[0] for f in findings]
                if expected_unsafe:
                    self.assertEqual(rules, ['js.taint.xss'], (name, findings))
                else:
                    self.assertEqual(rules, [], (name, findings))

    def test_borrowed_array_fill_unsupported_invocations_report_incomplete(self):
        from ubs_core.analyzers import taint_js
        for name, body in [
            ('proto-fill-apply',
             'const a = ["safe"]; Array.prototype.fill.apply(a, [req.query.html]); res.send(a[0]);'),
            ('reflect-apply-fill',
             'const a = ["safe"]; Reflect.apply(Array.prototype.fill, a, [req.query.html]); res.send(a[0]);'),
            ('non-array-receiver-call',
             'Array.prototype.fill.call(obj, req.query.html); res.send(obj[0]);'),
            ('bare-fill-call',
             'const fn = Array.prototype.fill; fn(req.query.html); res.send("ok");'),
        ]:
            with self.subTest(case=name):
                with self.assertRaises(taint_js.AnalysisLimit, msg=name):
                    self.scan_file(body)

    def test_borrowed_array_fill_mutated_or_deleted_function_prototype_call_reports_incomplete(self):
        from ubs_core.analyzers import taint_js
        node_bin = shutil.which('node')
        prefix = (
            'const _origCall = Function.prototype.call; '
            'const req = {query:{html:"<UNTRUSTED>"}}; const outputs = []; '
            'const res = {send: value => outputs.push(value)}; '
        )
        restore = ' Object.defineProperty(Function.prototype, "call", { value: _origCall, writable: true, configurable: true }); '
        noop_cases = [
            ('func-proto-call-noop-direct',
             'Function.prototype.call = function() {}; const a = [req.query.html]; Array.prototype.fill.call(a, "clean"); res.send(a[0]);'),
            ('func-proto-call-noop-saved',
             'Function.prototype.call = function() {}; const a = [req.query.html]; const fn = Array.prototype.fill; fn.call(a, "clean"); res.send(a[0]);'),
            ('func-proto-call-noop-literal',
             'Function.prototype.call = function() {}; const a = [req.query.html]; [].fill.call(a, "clean"); res.send(a[0]);'),
        ]
        for name, body in noop_cases:
            with self.subTest(case=name):
                if node_bin is not None:
                    node = subprocess.run(
                        [node_bin, '-e', prefix + body + restore + 'console.log(JSON.stringify(outputs));'],
                        capture_output=True, text=True, timeout=15,
                    )
                    self.assertEqual(node.returncode, 0, node.stdout + node.stderr)
                    self.assertIn('<UNTRUSTED>', node.stdout, (name, node.stdout))
                with self.assertRaises(taint_js.AnalysisLimit, msg=name):
                    self.scan_file(body)
        defineprop_body = 'Object.defineProperty(Function.prototype, "call", { value: function() {}, configurable: true }); const a = [req.query.html]; Array.prototype.fill.call(a, "clean"); res.send(a[0]);'
        if node_bin is not None:
            node = subprocess.run(
                [node_bin, '-e', prefix + defineprop_body + restore + 'console.log(JSON.stringify(outputs));'],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(node.returncode, 0, node.stdout + node.stderr)
            self.assertIn('<UNTRUSTED>', node.stdout, node.stdout)
        self.assertEqual([f[0] for f in self.scan_file(defineprop_body)], ['js.taint.xss'])
        delete_body = 'delete Function.prototype.call; const a = [req.query.html]; Array.prototype.fill.call(a, "clean"); res.send(a[0]);'
        if node_bin is not None:
            node = subprocess.run(
                [node_bin, '-e', prefix + 'let msg = ""; try { ' + delete_body + ' } catch (e) { msg = "THREW:" + e.name; }' + restore + 'console.log(msg);'],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(node.returncode, 0, node.stdout + node.stderr)
            self.assertIn('THREW:TypeError', node.stdout, node.stdout)
        with self.assertRaises(taint_js.AnalysisLimit, msg='delete-func-proto-call'):
            self.scan_file(delete_body)

if __name__ == '__main__':
    unittest.main(verbosity=2)
