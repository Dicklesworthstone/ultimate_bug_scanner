"""GH #180: recursive summary isolation across callers, effects and rules."""
from __future__ import annotations

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
        findings = json.loads(result.stdout)
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


if __name__ == '__main__':
    unittest.main()
