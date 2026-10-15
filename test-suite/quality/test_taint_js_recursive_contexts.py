"""GH #180: recursive summary isolation across callers, effects and rules."""
from __future__ import annotations

from collections import deque
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / 'modules/helpers'

# Run each case in a fresh, time-bounded process. A work-limit exception must
# fail the test, never turn an unfinished analysis into an empty findings list.
SCAN = '''\
import json, sys
from pathlib import Path
from ubs_core.analyzers.taint_js import scan_file_findings
print(json.dumps(list(scan_file_findings(Path(sys.argv[1])))))
'''


class RecursiveContextIsolationTests(unittest.TestCase):
    def scan(self, source, expected):
        source = textwrap.dedent(source).strip() + '\n'
        with tempfile.TemporaryDirectory(prefix='ubs-recursive-context-') as scratch:
            path = Path(scratch) / 'case.js'
            path.write_text(source, encoding='utf-8')
            env = dict(os.environ, PYTHONPATH=str(HELPERS), PYTHONDONTWRITEBYTECODE='1')
            try:
                result = subprocess.run([sys.executable, '-c', SCAN, str(path)],
                                        env=env, capture_output=True, text=True, timeout=30)
            except subprocess.TimeoutExpired as exc:
                self.fail(f'recursive analysis did not converge\n{source}\n{exc}')
        self.assertEqual(result.returncode, 0, source + result.stdout + result.stderr)
        try:
            findings = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f'invalid recursive-analysis JSON: {exc}\n{source}\n'
                      f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
        lines = source.splitlines()
        wanted = sorted((rule, next(i for i, line in enumerate(lines, 1)
                                   if '// ' + marker in line))
                        for rule, marker in expected)
        self.assertEqual(sorted((rule, line) for rule, line, _col, _trace in findings),
                         wanted, (source, findings))
        return {lines[line - 1].split('// ', 1)[1]: trace
                for _rule, line, _col, trace in findings}

    def test_shared_inner_site_preserves_each_callers_source(self):
        declarations = {
            'first': 'const first = wrap({html: req.query.first});',
            'second': 'const second = wrap({html: req.query.second});',
            'clean': 'const clean = wrap({html: "safe"});',
        }
        # Exercise scheduling in both tainted/clean orders and check provenance,
        # not merely the number of XSS findings.
        for order in itertools.permutations(declarations):
            with self.subTest(order=order):
                source = '''
function copy(box, n) {
  if (n > 0) return copy(box, n - 1);
  return {html: box.html, kind: "constant"};
}
function wrap(box) { return copy(box, 3); }
''' + '\n'.join(declarations[key] for key in order) + '''
res.send(first.html); // first
res.send(second.html); // second
res.send(clean.html); // clean
res.send(first.kind); // constant
'''
                traces = self.scan(source, [('js.taint.xss', 'first'), ('js.taint.xss', 'second')])
                for key, other in (('first', 'second'), ('second', 'first')):
                    self.assertIn('req.query.' + key, traces[key])
                    self.assertNotIn('req.query.' + other, traces[key])

    def test_mutual_recursion_keeps_borrowed_aliases_and_callers_separate(self):
        self.scan('''
function left(box, value, n) {
  if (n > 0) right(box, value, n - 1);
  else box.html = value;
}
function right(box, value, n) { left(box, value, n); }
const dirty = {html: "safe"};
const dirtyAlias = dirty;
const clean = {html: "safe"};
const cleanAlias = clean;
left(dirty, req.query.html, 3);
left(clean, "safe", 3);
res.send(dirtyAlias.html); // dirty
res.send(cleanAlias.html); // clean
''', [('js.taint.xss', 'dirty')])

    def test_recursive_exception_objects_preserve_fields_and_callers(self):
        self.scan('''
function reject(box, n) {
  if (n > 0) return reject(box, n - 1);
  throw {html: box.html, kind: "constant"};
}
try { reject({html: req.query.html}, 3); }
catch (error) {
  res.send(error.html); // dirty
  res.send(error.kind); // constant
}
try { reject({html: "safe"}, 3); }
catch (error) { res.send(error.html); } // clean
''', [('js.taint.xss', 'dirty')])

    def test_cyclic_borrowed_inputs_converge_without_cross_contamination(self):
        self.scan('''
function visit(node, n) {
  if (n > 0) return visit(node.next, n - 1);
  return {html: node.html};
}
const dirty = {html: req.query.html};
dirty.next = dirty;
const clean = {html: "safe"};
clean.next = clean;
const a = visit(dirty, 3);
const b = visit(clean, 3);
res.send(a.html); // dirty
res.send(b.html); // clean
''', [('js.taint.xss', 'dirty')])

    def test_nested_formal_shadowing_does_not_capture_outer_taint(self):
        self.scan('''
function wrap(label) {
  function get(label) { return {note: label}; }
  return get("safe");
}
res.send(wrap(req.query.label).note); // clean
''', [])

    def test_nested_recursive_capture_preserves_distinct_source_traces(self):
        traces = self.scan('''
function wrap(label) {
  function get(n) {
    if (n > 0) return get(n - 1);
    return {note: label};
  }
  return get(3);
}
const a = wrap(req.query.first);
const b = wrap(req.query.second);
const c = wrap("safe");
res.send(a.note); // first
res.send(b.note); // second
res.send(c.note); // clean
''', [('js.taint.xss', 'first'), ('js.taint.xss', 'second')])
        self.assertIn('req.query.first', traces['first'])
        self.assertNotIn('req.query.second', traces['first'])
        self.assertIn('req.query.second', traces['second'])
        self.assertNotIn('req.query.first', traces['second'])

    def test_widened_summaries_keep_sanitizers_rule_specific(self):
        self.scan('''
function copy(box, n) {
  if (n > 0) return copy(box, n - 1);
  return {html: box.html};
}
const box = copy({html: DOMPurify.sanitize(req.query.html)}, 3);
res.send(box.html); // sanitized-xss
// An HTML sanitizer must not remove code-injection taint.
eval(box.html); // eval
''', [('js.taint.eval', 'eval')])

    def test_helpers_inside_one_recursion_keep_each_source_and_clean_call(self):
        declarations = {
            'first': 'const first = wrap(req.query.first);',
            'second': 'const second = wrap(req.query.second);',
            'clean': 'const clean = wrap("safe");',
        }
        # The same inner mk() site is reached through three calls to wrap()
        # INSIDE one widened entry, not through three outside recursion roots.
        for order in itertools.permutations(declarations):
            with self.subTest(order=order):
                traces = self.scan('''
function mk(value) { return {html: value, kind: "constant"}; }
function wrap(value) { return mk(value); }
function walk(n) {
  if (n > 0) walk(n - 1);
''' + '\n'.join(declarations[key] for key in order) + '''
  res.send(first.html); // first
  res.send(second.html); // second
  res.send(clean.html); // clean
  res.send(first.kind); // constant
}
walk(3);
''', [('js.taint.xss', 'first'), ('js.taint.xss', 'second')])
                for key, other in (('first', 'second'), ('second', 'first')):
                    self.assertIn('req.query.' + key, traces[key])
                    self.assertNotIn('req.query.' + other, traces[key])

    def test_mutual_recursion_preserves_helper_borrowed_mutations(self):
        self.scan('''
function set(box, value) { box.html = value; }
function left(n) {
  if (n > 0) right(n - 1);
  const dirty = {html: "safe"};
  const clean = {html: "safe"};
  const alias = dirty;
  set(dirty, req.query.html);
  set(clean, "safe");
  res.send(alias.html); // dirty
  res.send(clean.html); // clean
}
function right(n) { left(n); }
left(3);
''', [('js.taint.xss', 'dirty')])

    def test_helper_exceptions_inside_recursion_do_not_taint_clean_catch(self):
        self.scan('''
function reject(value) { throw {html: value, kind: "constant"}; }
function walk(n) {
  if (n > 0) walk(n - 1);
  try { reject(req.query.html); }
  catch (error) {
    res.send(error.html); // dirty
    res.send(error.kind); // constant
  }
  try { reject("safe"); }
  catch (error) { res.send(error.html); } // clean
}
walk(3);
''', [('js.taint.xss', 'dirty')])

    def test_helpers_inside_recursion_preserve_rule_specific_sanitization(self):
        self.scan('''
function mk(value) { return {html: value}; }
function walk(n) {
  if (n > 0) walk(n - 1);
  const dirty = mk(req.query.html);
  const clean = mk(DOMPurify.sanitize(req.query.html));
  res.send(dirty.html); // dirty
  res.send(clean.html); // sanitized
  eval(clean.html); // eval
}
walk(3);
''', [('js.taint.xss', 'dirty'), ('js.taint.eval', 'eval')])

    def test_catch_rest_return_keeps_fields_and_callers_without_crashing(self):
        for recurse in ('', 'if (n > 0) return unwrap(box, n - 1);'):
            with self.subTest(recursive=bool(recurse)):
                self.scan('''
function unwrap(box, n) {
''' + recurse + '''
  try { throw box; }
  catch ({skip, ...rest}) { return rest; }
}
const a = unwrap({skip: "safe", html: req.query.html, kind: "constant"}, 3);
const b = unwrap({skip: req.query.secret, html: "safe", kind: "constant"}, 3);
res.send(a.html); // dirty
res.send(a.kind); // constant
res.send(b.html); // clean
res.send(b.skip); // excluded
''', [('js.taint.xss', 'dirty')])

    def test_catch_array_rest_escapes_through_recursive_wrappers(self):
        self.scan('''
function tail(values) {
  try { throw values; }
  catch ([skip, ...rest]) { return rest; }
}
function walk(n) {
  if (n > 0) walk(n - 1);
  const a = tail(["skip", req.query.html]);
  const b = tail([req.query.secret, "safe"]);
  res.send(a[0]); // dirty
  res.send(b[0]); // clean
  res.send(a.length); // count
}
walk(3);
''', [('js.taint.xss', 'dirty')])

    def test_catch_rest_preserves_nested_alias_mutation(self):
        self.scan('''
function unwrap(box) {
  try { throw box; } catch ({skip, ...rest}) { return rest; }
}
const nested = {html: "safe"};
const result = unwrap({skip: req.query.secret, nested: nested});
nested.html = req.query.html;
res.send(result.nested.html); // dirty
res.send(result.skip); // excluded
''', [('js.taint.xss', 'dirty')])

    def test_recursive_clones_called_inside_recursion_keep_callers_separate(self):
        self.scan('''
function clone(o) {
  if (Array.isArray(o)) return o.map(clone);
  if (o && typeof o === "object") {
    const result = {};
    for (const key of Object.keys(o)) result[key] = clone(o[key]);
    return result;
  }
  return o;
}
function walk(n) {
  if (n > 0) walk(n - 1);
  const dirty = clone({html: req.query.html});
  const clean = clone({html: "safe"});
  res.send(dirty.html); // dirty
  res.send(clean.html); // clean
}
walk(3);
''', [('js.taint.xss', 'dirty')])


class RecursiveHeapTransferTests(unittest.TestCase):
    """Check complete origin sets and heap identities, not one chosen witness."""

    @classmethod
    def setUpClass(cls):
        if str(HELPERS) not in sys.path:
            sys.path.insert(0, str(HELPERS))
        from ubs_core.analyzers import taint_js
        cls.js = taint_js

    def setUp(self):
        js = self.js
        self.engine = js._Engine.__new__(js._Engine)
        self.engine.budget = js.Budget()
        self.engine.widened_calls = {}
        self.engine.pending = deque()
        self.engine.queued = set()
        self.scope = object()
        self.root = (17, object())
        self.first = js._Fact([js._Trace(('source', 'first'), ('req.query.first',))])
        self.second = js._Fact([js._Trace(('source', 'second'), ('req.query.second',))])
        self.clean = js._Fact()

    def origins(self, fact):
        return {trace.origin for trace in fact}

    def test_widened_allocation_histories_remain_bounded_and_keep_every_source(self):
        js = self.js
        state, incoming = js._State(), js._State()
        expected = None
        for index in range(1024):
            ref = ('factory', 70, frozenset({index, index + 1}))
            value = (self.first, self.second, self.clean)[index % 3]
            output = js._HeapOutput({ref: {'html': value, 'kind': self.clean}}, set(), {})
            returned = self.engine.apply_heap_output(
                incoming, state, output, {}, js._Fact(refs=[ref]), index, widened=self.root)
            if expected is None:
                expected = returned
            self.assertEqual(returned, expected)
            self.assertEqual(len(state.heap), 1)
        ref, = js._refs(expected)
        self.assertEqual(self.origins(state.heap[ref]['html']),
                         {('source', 'first'), ('source', 'second')})
        self.assertFalse(state.heap[ref]['kind'])
        self.assertEqual(state.weak_refs, {ref})
        # This is a deterministic work bound, not an elapsed-time or RSS claim.
        self.assertGreater(self.engine.budget.remaining, 490_000)

    def test_widened_entries_do_not_share_fresh_allocations_or_sources(self):
        js = self.js
        state, incoming = js._State(), js._State()
        allocation = ('factory', 70)
        references = []
        for root, value in ((self.root, self.first), ((18, object()), self.clean)):
            output = js._HeapOutput({allocation: {'html': value}}, set(), {})
            returned = self.engine.apply_heap_output(
                incoming, state, output, {}, js._Fact(refs=[allocation]), 23, widened=root)
            ref, = js._refs(returned)
            references.append(ref)
        dirty, clean = references
        self.assertNotEqual(dirty, clean)
        self.assertEqual(set(state.heap), {dirty, clean})
        self.assertEqual(self.origins(state.heap[dirty]['html']), {('source', 'first')})
        self.assertFalse(state.heap[clean]['html'])
        self.assertEqual(state.weak_refs, {dirty, clean})

    def test_borrowed_mutations_keep_aliases_and_translate_fresh_children(self):
        js = self.js
        borrowed, fresh = ('caller', 11), ('callee', 29)
        incoming = js._State({'alias': js._Fact(refs=[borrowed])})
        incoming.heap[borrowed] = {'html': self.clean}
        before = incoming.copy()
        state = incoming.copy()
        output = js._HeapOutput({
            borrowed: {'html': self.first, 'child': js._Fact(refs=[fresh])},
            fresh: {'html': self.second},
        }, set(), {})
        result = self.engine.apply_heap_output(
            incoming, state, output, {}, js._Fact(refs=[borrowed]), 31, widened=self.root)
        self.assertEqual(js._refs(result), {borrowed})
        self.assertEqual(js._refs(state['alias']), {borrowed})
        child, = js._refs(state.heap[borrowed]['child'])
        self.assertNotEqual(child, fresh)
        self.assertEqual(self.origins(state.heap[borrowed]['html']), {('source', 'first')})
        self.assertEqual(self.origins(state.heap[child]['html']), {('source', 'second')})
        self.assertNotIn(borrowed, state.weak_refs)
        self.assertIn(child, state.weak_refs)
        self.assertEqual(incoming, before)
        self.assertEqual(js._refs(output.heap[borrowed]['child']), {fresh})

    def test_fresh_cycles_and_captured_writes_use_the_same_translation(self):
        js = self.js
        outer = object()
        cell = (outer, 0, 'result')
        allocation = ('factory', 70)
        value = js._Fact(refs=[allocation])
        incoming, state = js._State(), js._State()
        output = js._HeapOutput({allocation: {'self': value, 'html': self.first}}, set(), {})
        returned = self.engine.apply_heap_output(
            incoming, state, output, {cell: value}, value, 31, widened=self.root)
        ref, = js._refs(returned)
        self.assertEqual(js._refs(state.heap[ref]['self']), {ref})
        self.assertEqual(js._refs(state.cells[cell]), {ref})
        self.assertEqual(js._refs(state['result']), {ref})
        self.assertEqual(state.owners['result'], cell)
        self.assertIn(cell, state.written_cells)
        self.assertEqual(self.origins(state.heap[ref]['html']), {('source', 'first')})
        self.assertEqual(set(state.heap), {ref})

    def test_captured_write_does_not_overwrite_a_shadowing_local(self):
        js = self.js
        captured, local = (object(), 0, 'label'), (object(), 1, 'label')
        state = js._State({'label': self.clean})
        state.owners['label'] = local
        output = js._HeapOutput({}, set(), {})
        self.engine.apply_heap_output(
            js._State(), state, output, {captured: self.first}, self.clean, 31,
            widened=self.root)
        self.assertEqual(self.origins(state.cells[captured]), {('source', 'first')})
        self.assertFalse(state['label'])
        self.assertEqual(state.owners['label'], local)
        self.assertEqual(state.written_cells, {captured})

    def test_normal_and_exceptional_transfers_do_not_share_mutable_state(self):
        js = self.js
        borrowed = ('caller', 11)
        incoming = js._State()
        incoming.heap[borrowed] = {'html': self.clean}
        normal, exceptional = incoming.copy(), incoming.copy()
        for state, value in ((normal, self.first), (exceptional, self.second)):
            output = js._HeapOutput({borrowed: {'html': value}}, set(), {})
            self.engine.apply_heap_output(
                incoming, state, output, {}, self.clean, 31, widened=self.root)
        self.assertEqual(self.origins(normal.heap[borrowed]['html']), {('source', 'first')})
        self.assertEqual(self.origins(exceptional.heap[borrowed]['html']), {('source', 'second')})
        self.assertFalse(incoming.heap[borrowed]['html'])
        self.assertIsNot(normal.heap[borrowed], exceptional.heap[borrowed])

    def test_heap_and_cell_only_input_growth_requeues_but_stable_input_does_not(self):
        js = self.js
        ref, cell = ('caller', 11), (object(), 0, 'label')
        incoming = js._State()
        incoming.heap[ref] = {'html': self.clean}
        incoming.cells[cell] = self.clean
        bound = {'box': js._Fact(refs=[ref])}
        ancestors = frozenset({self.scope})
        context = self.engine.widened_call(
            self.scope, 'js.taint.xss', self.root, 31, bound, incoming, ancestors)
        for changed in ('heap', 'cell'):
            with self.subTest(changed=changed):
                self.engine.pending.clear()
                self.engine.queued.clear()
                incoming = incoming.copy()
                if changed == 'heap':
                    incoming.heap[ref]['html'] = self.first
                else:
                    incoming.cells[cell] = self.second
                again = self.engine.widened_call(
                    self.scope, 'js.taint.xss', self.root, 32, bound, incoming, ancestors)
                self.assertIs(again, context)
                self.assertEqual(list(self.engine.pending), [context])
        self.assertEqual(self.origins(context.incoming.heap[ref]['html']), {('source', 'first')})
        self.assertEqual(self.origins(context.incoming.cells[cell]), {('source', 'second')})
        self.engine.pending.clear()
        self.engine.queued.clear()
        self.engine.widened_call(
            self.scope, 'js.taint.xss', self.root, 33, bound, incoming, ancestors)
        self.assertFalse(self.engine.pending)
        self.assertFalse(self.engine.queued)
        self.assertEqual(len(self.engine.widened_calls), 1)

    def test_recursive_array_lengths_widen_and_rule_domains_remain_separate(self):
        js = self.js
        ref = ('caller', 11)
        contexts = []
        for rule, value in (('js.taint.xss', self.clean), ('js.taint.eval', self.first)):
            incoming = js._State()
            incoming.heap[ref] = {'0': value}
            incoming.array_lengths[ref] = 1
            context = self.engine.widened_call(
                self.scope, rule, self.root, 31, {'array': js._Fact(refs=[ref])},
                incoming, frozenset({self.scope}))
            contexts.append(context)
            self.assertIsNone(context.incoming.array_lengths[ref])
        self.assertIsNot(contexts[0], contexts[1])
        self.assertFalse(contexts[0].incoming.heap[ref]['0'])
        self.assertEqual(self.origins(contexts[1].incoming.heap[ref]['0']), {('source', 'first')})
        self.assertEqual(len(self.engine.widened_calls), 2)

    def test_backedges_reuse_ancestors_but_sibling_helpers_remain_distinct(self):
        js = self.js
        rule = 'js.taint.xss'
        helper = object()
        ancestors = frozenset({self.scope})
        root = self.engine.widened_call(
            self.scope, rule, self.root, 31, {}, js._State(), ancestors)
        first = self.engine.widened_call(
            helper, rule, self.root, 40, {'value': self.first}, js._State(),
            ancestors | {helper}, caller=root)
        second = self.engine.widened_call(
            helper, rule, self.root, 41, {'value': self.clean}, js._State(),
            ancestors | {helper}, caller=root)
        self.assertIsNot(first, second)
        self.assertEqual(self.origins(first.bound['value']), {('source', 'first')})
        self.assertFalse(second.bound['value'])
        for location in range(1024):
            again = self.engine.widened_call(
                self.scope, rule, self.root, location, {}, js._State(),
                ancestors | {helper}, caller=first)
            self.assertIs(again, root)
        self.assertEqual(len(self.engine.widened_calls), 3)
        self.assertIs(first.widened_parent, root)
        self.assertIsNone(root.widened_parent)

    def test_tagged_allocation_sites_keep_discriminators_and_finite_histories(self):
        js = self.js
        for widened in (None, self.root):
            with self.subTest(widened=widened is not None):
                state = js._State()
                refs = [('factory', 70), ('factory', 70, 'catch-rest'),
                        ('factory', 70, 'commonjs')]
                output = js._HeapOutput({ref: {'html': value}
                                        for ref, value in zip(refs, (self.first, self.clean, self.second))},
                                       set(), {})
                result = self.engine.apply_heap_output(
                    js._State(), state, output, {}, js._Fact(refs=refs), 17, widened=widened)
                self.assertEqual(len(js._refs(result)), 3)
                self.assertEqual(len(state.heap), 3)
                self.assertEqual({ref[:-1] for ref in state.heap}, set(refs))
                for ref in state.heap:
                    self.assertIsInstance(ref[-1], frozenset)
                    self.assertEqual(js._collapsed(ref), widened is not None)
                again = self.engine.apply_heap_output(
                    js._State(), js._State(),
                    js._HeapOutput(state.heap, state.weak_refs, state.array_lengths),
                    {}, result, 19, widened=widened)
                self.assertEqual({ref[:-1] for ref in js._refs(again)}, set(refs))
                if widened is not None:
                    self.assertEqual(again, result)
                else:
                    self.assertTrue(all(ref[-1] == {17, 19} for ref in js._refs(again)))

    def test_full_solver_keeps_all_helper_source_origins_separate(self):
        js = self.js
        source = '''function mk(value) { return {html: value}; }
function wrap(value) { return mk(value); }
function walk(n) {
  if (n > 0) walk(n - 1);
  const a = wrap(req.query.first);
  const b = wrap(req.query.second);
  const c = wrap("safe");
  res.send(a.html);
  res.send(b.html);
  res.send(c.html);
}
walk(3);
'''
        engine = js._Engine(*js.lexical_views(source))
        engine.budget = js.Budget(engine.work_limit)
        engine.pending, engine.queued = deque(reversed(engine.scopes)), set(engine.scopes)
        found = engine.rule_findings('js.taint.xss')
        by_line = {source[:location].count('\n') + 1: self.origins(fact)
                   for (location, _rule, _label), fact in found.items()}
        self.assertEqual(by_line, {
            8: {('source', 'req.query.first')},
            9: {('source', 'req.query.second')},
        })
        self.assertGreater(engine.budget.remaining, 0)


if __name__ == '__main__':
    unittest.main()
