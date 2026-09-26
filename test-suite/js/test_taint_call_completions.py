"""D6: local call completion, finalizer replacement and evaluation order."""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules' / 'helpers'))
from ubs_core.analyzers import taint_js
from ubs_core.registry import RunContext


def scan(source):
    with tempfile.TemporaryDirectory(prefix='ubs-js-completions-') as tmp:
        path = Path(tmp) / 'handler.ts'
        path.write_text(source + '\n', encoding='utf-8')
        return list(taint_js.run(RunContext(lang='javascript', files=[path])))


class CallCompletionTests(unittest.TestCase):
    def run(self, result=None):
        started = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)
        result = super().run(result)
        failed = any(test is self for test, _ in (*result.failures, *result.errors))
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} ({time.monotonic() - started:.3f}s)', flush=True)
        return result

    def check(self, source, *expected):
        findings = scan(source)
        self.assertEqual(Counter(f['rule'].rsplit('.', 1)[-1] for f in findings),
                         Counter(expected), (source, findings))
        return findings

    def test_finalizer_replaces_pending_return_value(self):
        self.check('function clean() { try { return req.query.html; } finally { return "safe"; } } res.send(clean());')
        self.check('function read() { try { return "safe"; } finally { return req.query.html; } } res.send(read());', 'xss')

    def test_conditional_finalizer_keeps_both_return_values(self):
        self.check('function read() { try { return req.query.html; } finally { if (flag) return "safe"; } } res.send(read());', 'xss')
        self.check('function read() { try { return "safe"; } finally { if (flag) return req.query.html; } } res.send(read());', 'xss')

    def test_finalizer_updates_store_without_retroactively_changing_return(self):
        self.check('let out = req.query.html; function read() { try { return out; } finally { out = "safe"; } } '
                   'res.send(read()); res.send(out);', 'xss')
        self.check('let out = "safe"; function read() { try { return out; } finally { out = req.query.html; } } '
                   'res.send(read()); res.send(out);', 'xss')

    def test_return_in_finally_cancels_pending_throw(self):
        self.check('let out = "safe"; function read() { try { throw Error(); } '
                   'finally { out = req.query.html; return; } } read(); res.send(out);', 'xss')

    def test_throw_in_finally_cancels_pending_return(self):
        self.check('function read() { try { return req.query.html; } finally { throw Error(); } } res.send(read());')
        self.check('let out = "safe"; function read() { try { return; } finally { out = req.query.html; throw Error(); } } '
                   'try { read(); } catch (error) { res.send(out); }', 'xss')

    def test_exceptional_write_flows_only_to_handler(self):
        prefix = 'let out = "safe"; function put(value) { out = value; throw Error(); } '
        self.check(prefix + 'try { put(req.query.html); } catch (error) { res.send(out); }', 'xss')
        self.check(prefix + 'put(req.query.html); res.send(out);')

    def test_finalizer_clear_transforms_exceptional_writes(self):
        self.check('let out = "safe"; function put(v) { try { out = v; throw Error(); } finally { out = "safe"; } } '
                   'try { put(req.query.html); } catch (error) { res.send(out); }')

    def test_nested_finalizers_replace_in_order(self):
        self.check('function read() { try { try { return req.query.html; } finally { return "safe"; } } '
                   'finally { return "also safe"; } } res.send(read());')
        self.check('function read() { try { try { return req.query.html; } finally { return "safe"; } } '
                   'finally { return req.query.other; } } res.send(read());', 'xss')

    def test_throw_from_default_skips_body_and_reaches_handler(self):
        prefix = ('let out = "safe"; function fail() { out = req.query.html; throw Error(); } '
                  'function accept(v = fail()) { out = "body"; } ')
        self.check(prefix + 'try { accept(); } catch (error) { res.send(out); }', 'xss')
        self.check(prefix + 'accept(); res.send(out);')
        self.check(prefix + 'accept("explicit"); res.send(out);')

    def test_nonreturning_argument_prevents_sink_call(self):
        self.check('function fail() { throw Error(); } res.send(req.query.html, fail());')
        self.check('function fail() { throw Error(); } res.send(fail(), req.query.html);')
        self.check('function okay() { return ""; } res.send(req.query.html, okay());', 'xss')

    def test_branch_with_nonreturning_call_does_not_pollute_return(self):
        self.check('function fail() { throw Error(); } function read() { if (flag) return fail(); return "safe"; } res.send(read());')
        self.check('function fail() { throw Error(); } function read() { if (flag) return fail(); return req.query.html; } res.send(read());', 'xss')

    def test_nonreturning_conditions_prevent_body_and_continuation(self):
        for statement in ('if (fail()) { res.send(req.query.html); }',
                          'while (fail()) { res.send(req.query.html); }',
                          'for (fail(); flag; update()) { res.send(req.query.html); }',
                          'switch (fail()) { case 1: res.send(req.query.html); }'):
            with self.subTest(statement=statement):
                self.check('function fail() { throw Error(); } ' + statement + ' res.send(req.query.html);')

    def test_nonreturning_recursion_converges_without_inventing_a_return(self):
        # A subprocess makes a regression fail promptly rather than hanging CI.
        source = ('let left = req.query.html, right = "safe"; function spin() { spin(); '
                  'const tmp = left; left = right; right = tmp; } spin(); res.send(left); res.send(right);')
        program = ('import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); '
                   'from ubs_core.analyzers import taint_js; '
                   'text, code = taint_js.lexical_views(sys.argv[2]); '
                   'assert list(taint_js._Engine(text, code).findings()) == []')
        result = subprocess.run([sys.executable, '-c', program, str(ROOT / 'modules/helpers'), source],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_recursive_base_case_still_propagates_writes(self):
        self.check('let out = "safe"; function first(v) { second(v); } '
                   'function second(v) { if (flag) first(v); else out = v; } '
                   'first(req.query.html); res.send(out);', 'xss')

    def test_long_call_chain_keeps_reachable_completion(self):
        helpers = ''.join(f'function f{i}(v) {{ f{i+1}(v); }} ' for i in range(40))
        self.check('let out = "safe"; ' + helpers + 'function f40(v) { out = v; } f0(req.query.html); res.send(out);', 'xss')

    def test_reads_before_and_after_call_use_their_own_store(self):
        prefix = 'let out = req.query.html; function clear() { out = "safe"; return ""; } '
        self.check(prefix + 'res.send(out + clear());', 'xss')
        self.check(prefix + 'res.send(clear() + out);')
        self.check(prefix + 'res.send(`${out}${clear()}`);', 'xss')
        self.check(prefix + 'res.send(`${clear()}${out}`);')

    def test_compound_assignment_reads_left_before_calling_right(self):
        prefix = 'let out = req.query.html; function clear() { out = "safe"; return ""; } '
        self.check(prefix + 'out += clear(); res.send(out);', 'xss')
        self.check(prefix + 'res.send(out += clear());', 'xss')
        self.check(prefix + 'out = clear(); res.send(out);')

    def test_argument_evaluation_order_preserves_read_before_mutation(self):
        prefix = ('let out = req.query.html; function clear() { out = "safe"; return ""; } '
                  'function first(a, b) { return a; } function second(a, b) { return b; } ')
        self.check(prefix + 'res.send(first(out, clear()));', 'xss')
        self.check(prefix + 'res.send(second(clear(), out));')

    def test_callee_is_selected_before_argument_rebind(self):
        findings = self.check('function clean(v) { return "safe"; } function identity(v) { return v; } '
                              'function rebind() { clean = identity; return req.query.html; }\n'
                              'res.send(clean(rebind()));\nres.send(clean(req.query.html));', 'xss')
        self.assertEqual(findings[0]['line'], 3)

    def test_sanitizer_identity_is_selected_before_argument_rebind(self):
        self.check('function rebind() { DOMPurify = external; return req.query.html; } '
                   'res.send(DOMPurify.sanitize(rebind())); res.send(DOMPurify.sanitize(req.query.html));', 'xss')


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'set UBS_TAINT_E2E=1 for real scanner checks')
class CallCompletionScannerTests(unittest.TestCase):
    def test_actual_scanner_completion_and_ordering(self):
        cases = [
            ('before-clear', 'let out=req.query.html; function clear(){out="safe";return "";} res.send(out+clear());', {'xss'}),
            ('after-clear', 'let out=req.query.html; function clear(){out="safe";return "";} res.send(clear()+out);', set()),
            ('final-return', 'function read(){try{return req.query.html;}finally{return "safe";}} res.send(read());', set()),
            ('thrown-write', 'let out="safe";function put(v){out=v;throw Error();}try{put(req.query.html);}catch(e){res.send(out);}', {'xss'}),
            ('no-continuation', 'let out="safe";function put(v){out=v;throw Error();}put(req.query.html);res.send(out);', set()),
        ]
        for name, source, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='ubs-js-completion-cli-') as tmp:
                target = Path(tmp) / 'handler.ts'
                target.write_text(source + '\n', encoding='utf-8')
                result = subprocess.run([str(ROOT / 'ubs'), str(target), '--ci', '--only=js', '--format=json'],
                                        cwd=tmp, capture_output=True, text=True, timeout=120)
                artifacts = ROOT / 'test-suite/artifacts/javascript-call-completions' / name
                artifacts.mkdir(parents=True, exist_ok=True)
                (artifacts / 'stdout.log').write_text(result.stdout)
                (artifacts / 'stderr.log').write_text(result.stderr)
                self.assertIn(result.returncode, (0, 1), result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['status'], 'ok', report)
                rules = set()

                def visit(value):
                    if isinstance(value, dict):
                        for key in ('rule', 'rule_id', 'ruleId'):
                            rule = value.get(key)
                            if isinstance(rule, str) and rule.startswith(('javascript.taint.', 'js.taint.')):
                                rules.add(rule.rsplit('.', 1)[-1])
                        for child in value.values():
                            visit(child)
                    elif isinstance(value, list):
                        for child in value:
                            visit(child)

                visit(report)
                self.assertEqual(rules, expected, (source, report))
                print('JS_COMPLETION_E2E_PASS', name, sorted(rules), flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
