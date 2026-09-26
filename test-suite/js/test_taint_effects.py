"""D6: call-site instantiation of captured/global scalar write summaries."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_js
from ubs_core.registry import RunContext


class CapturedWriteTests(unittest.TestCase):
    def run(self, result=None):
        start = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)
        result = super().run(result)
        failed = any(test is self for test, _ in (*result.failures, *result.errors))
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} ({time.monotonic() - start:.3f}s)', flush=True)
        return result

    def scan(self, source, *expected):
        with tempfile.TemporaryDirectory(prefix='ubs-js-effects-') as scratch:
            target = Path(scratch) / 'handler.js'
            target.write_text(source + '\n', encoding='utf-8')
            findings = list(taint_js.run(RunContext(lang='javascript', files=[target])))
        self.assertEqual(Counter(item['rule'].removeprefix('javascript.taint.') for item in findings),
                         Counter(expected), (source, findings))
        for item in findings:
            self.assertEqual(item['severity'], 'critical')
            self.assertGreater(item['line'], 0)
            self.assertGreater(item['col'], 0)
            self.assertIn(' -> ', item['message'])
        return findings

    def test_global_write_reaches_later_sink(self):
        findings = self.scan('let result; function store(x) { result = x; }\n'
                             'store(req.query.html);\nres.send(result);', 'xss')
        self.assertEqual(findings[0]['line'], 3)
        self.assertIn('store()', findings[0]['message'])
        self.assertIn('req.query.html', findings[0]['message'])

    def test_transitive_setter(self):
        self.scan('let result; function store(x) { result = x; }\n'
                  'function forward(y) { store(y); }\nforward(req.query.html); res.send(result);', 'xss')

    def test_uncalled_setter_does_not_mutate_global(self):
        self.scan('let result = "hello"; function store() { result = req.query.html; }\nres.send(result);')

    def test_setter_cannot_taint_an_earlier_read(self):
        findings = self.scan('let result = "hello"; function store(x) { result = x; }\n'
                             'res.send(result);\nstore(req.query.html);\nres.send(result);', 'xss')
        self.assertEqual(findings[0]['line'], 4)

    def test_definite_clean_setter_kills_old_taint(self):
        self.scan('let result = req.query.html; function clear() { result = "hello"; }\nclear(); res.send(result);')

    def test_definite_setter_overwrite_uses_last_value(self):
        self.scan('let result; function store(x) { result = x; }\n'
                  'store(req.query.html); store("hello"); res.send(result);')

    def test_caller_overwrite_kills_written_taint(self):
        self.scan('let result; function store(x) { result = x; }\n'
                  'store(req.query.html); result = "hello"; res.send(result);')

    def test_conditional_clean_setter_preserves_incoming_taint(self):
        self.scan('let result = req.query.html; function clear() { if (flag) result = "hello"; }\n'
                  'clear(); res.send(result);', 'xss')

    def test_both_clean_branches_kill_taint(self):
        self.scan('let result = req.query.html; function clear() {\n'
                  'if (flag) result = "a"; else result = "b"; }\nclear(); res.send(result);')

    def test_early_return_keeps_no_write_path(self):
        self.scan('let result = req.query.html; function clear() { if (flag) return; result = "hello"; }\n'
                  'clear(); res.send(result);', 'xss')

    def test_write_before_return_survives(self):
        self.scan('let result; function store(x) { result = x; return; }\n'
                  'store(req.query.html); res.send(result);', 'xss')

    def test_unreachable_write_after_return_does_not_escape(self):
        self.scan('let result; function store(x) { return; result = x; }\n'
                  'store(req.query.html); res.send(result);')

    def test_captured_write_instantiates_wrapper_parameter(self):
        self.scan('function wrap(x) { let value; function store(y) { value = y; }\n'
                  'store(x); return value; }\nres.send(wrap(req.query.html));', 'xss')

    def test_separate_wrapper_calls_keep_their_own_locals(self):
        self.scan('function wrap(x) { let value; function store(y) { value = y; }\n'
                  'store(x); return value; }\nconst bad = wrap(req.query.html);\n'
                  'const good = wrap("hello"); res.send(good);')

    def test_three_levels_of_captured_writes(self):
        self.scan('function wrap(x) { let value; function outer(y) {\n'
                  'function inner(z) { value = z; } inner(y); }\n'
                  'outer(x); return value; }\neval(wrap(req.query.code));', 'eval')

    def test_caller_local_cannot_redirect_global_setter(self):
        self.scan('let result; function store(x) { result = x; }\n'
                  'function caller() { let result = "hello"; store(req.query.html); res.send(result); }\n'
                  'caller(); res.send(result);', 'xss')

    def test_parameter_cannot_redirect_global_setter(self):
        self.scan('let result; function store(x) { result = x; }\n'
                  'function caller(result) { store(req.query.html); res.send(result); }\n'
                  'caller("hello"); res.send(result);', 'xss')

    def test_block_shadow_does_not_hide_global_write_after_block(self):
        findings = self.scan('let result; function store(x) { result = x; }\n'
                             '{ let result = "hello"; store(req.query.html); res.send(result); }\n'
                             'res.send(result);', 'xss')
        self.assertEqual(findings[0]['line'], 3)

    def test_block_local_setter_does_not_taint_outer_same_name(self):
        self.scan('let value = "hello";\n{ let value; function store(x) { value = x; }\n'
                  'store(req.query.html); }\nres.send(value);')

    def test_shadowed_local_assignment_is_not_exported(self):
        self.scan('let result = "hello"; function store(x) { let result = x; }\n'
                  'store(req.query.html); res.send(result);')

    def test_shadowed_parameter_assignment_is_not_exported(self):
        self.scan('let result = "hello"; function store(result) { result = req.query.html; }\n'
                  'store("hello"); res.send(result);')

    def test_sanitizer_domain_is_preserved_through_write(self):
        self.scan('let result; function store(x) { result = DOMPurify.sanitize(x); }\n'
                  'store(req.query.value); res.send(result); eval(result); db.query(result); shell.exec(result);',
                  'eval', 'sql', 'command')

    def test_setter_reads_capture_at_its_call_site(self):
        findings = self.scan('let source = "hello", result; function copy() { result = source; }\n'
                             'copy(); res.send(result);\nsource = req.query.html; copy();\n'
                             'res.send(result);', 'xss')
        self.assertEqual(findings[0]['line'], 4)

    def test_multiple_written_cells_use_one_incoming_snapshot(self):
        findings = self.scan('let a = req.query.html, b = "hello";\n'
                             'function swap() { const saved = a; a = b; b = saved; }\n'
                             'swap(); res.send(a);\nres.send(b);', 'xss')
        self.assertEqual(findings[0]['line'], 4)

    def test_compound_assignment_keeps_old_and_new_origins(self):
        self.scan('let result = "hello"; function append(x) { result += x; }\n'
                  'append(req.query.html); res.send(result);', 'xss')
        self.scan('let result = req.query.html; function append(x) { result += x; }\n'
                  'append("hello"); res.send(result);', 'xss')

    def test_while_clean_write_keeps_zero_iteration_path(self):
        self.scan('let result = req.query.html; function clear() { while (flag) { result = "hello"; } }\n'
                  'clear(); res.send(result);', 'xss')

    def test_do_clean_write_runs_at_least_once(self):
        self.scan('let result = req.query.html; function clear() { do { result = "hello"; } while (false); }\n'
                  'clear(); res.send(result);')

    def test_setter_called_from_loop(self):
        self.scan('let result; function store(x) { result = x; }\n'
                  'for (let i = 0; i < count; i++) { store(req.query.html); } res.send(result);', 'xss')

    def test_short_circuit_clean_write_keeps_bypass_path(self):
        self.scan('let result = req.query.html; function clear() { result = "hello"; }\n'
                  'flag && clear(); res.send(result);', 'xss')

    def test_conditional_setter_expression_retains_tainted_branch(self):
        self.scan('let result; function store(x) { result = x; }\n'
                  'flag ? store(req.query.html) : store("hello"); res.send(result);', 'xss')

    def test_recursive_write_summaries_converge(self):
        self.scan('let result; function a(x) { if (flag) return b(x); result = x; }\n'
                  'function b(y) { a(y); }\nb(req.query.html); res.send(result);', 'xss')

    def test_unseeded_recursive_write_stays_clean(self):
        self.scan('let result; function a(x) { if (flag) return b(x); result = x; }\n'
                  'function b(y) { a(y); }\nb("hello"); res.send(result);')

    def test_long_setter_chain_has_no_depth_cutoff(self):
        lines = ['let result;']
        lines += [f'function f{i}(x) {{ f{i + 1}(x); }}' for i in range(35)]
        lines += ['function f35(x) { result = x; }', 'f0(req.query.html); res.send(result);']
        self.scan('\n'.join(lines), 'xss')

    def test_existing_selftests(self):
        for name, check in taint_js.SELF_TESTS:
            with self.subTest(name=name):
                check()

    def test_finally_write_survives_return(self):
        self.scan('let result; function store(x) { try { return; } finally { result = x; } }\n'
                  'store(req.query.html); res.send(result);', 'xss')

    def test_finally_clean_write_replaces_pre_return_state(self):
        self.scan('let result = req.query.html; function clear() {\n'
                  'try { return; } finally { result = "hello"; } } clear(); res.send(result);')

    def test_finally_write_covers_both_normal_and_return_paths(self):
        self.scan('let result; function store(x) {\n'
                  'try { if (flag) return; } finally { result = x; } }\n'
                  'store(req.query.html); res.send(result);', 'xss')

    def test_finally_source_write_survives_break(self):
        self.scan('let result; function store(x) { while (flag) {\n'
                  'try { break; } finally { result = x; } } }\n'
                  'store(req.query.html); res.send(result);', 'xss')

    def test_default_parameter_setter_updates_callers_state(self):
        self.scan('let result; function store(x) { result = x; }\n'
                  'function trigger(value = store(req.query.html)) {}\n'
                  'trigger(); res.send(result);', 'xss')

    def test_default_setter_not_executed_with_explicit_argument(self):
        self.scan('let result; function store(x) { result = x; }\n'
                  'function trigger(value = store(req.query.html)) {}\n'
                  'trigger("hello"); res.send(result);')

    def test_default_setter_can_clear_captured_taint(self):
        self.scan('let result = req.query.html; function clear() { result = "hello"; }\n'
                  'function trigger(value = clear()) {} trigger(); res.send(result);')


if __name__ == '__main__':
    unittest.main(verbosity=2)
