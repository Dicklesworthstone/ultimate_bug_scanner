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
        before = len(result.failures) + len(result.errors) if result is not None else 0
        result = super().run(result)
        failed = len(result.failures) + len(result.errors) > before
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

    def test_exception_value_reaches_catch_parameter(self):
        self.check('function fail(v) { throw v; } try { fail(req.query.html); } '
                   'catch (error) { res.send(error); }', 'xss')
        self.check('const error = req.query.html; try { throw "safe"; } '
                   'catch (error) { res.send(error); }')

    def test_catch_parameter_is_restored_after_handler(self):
        self.check('let error = req.query.html; try { throw "safe"; } '
                   'catch (error) { error = "clean"; } res.send(error);', 'xss')

    def test_normal_helper_does_not_execute_catch(self):
        self.check('function okay() { return "safe"; } try { okay(); } '
                   'catch (error) { res.send(req.query.html); }')

    def test_exceptional_heap_write_reaches_only_handler(self):
        prefix = 'function fail(o, v) { o.html = v; throw "failure"; } const o = {}; '
        self.check(prefix + 'try { fail(o, req.query.html); } catch(e) { res.send(o.html); }', 'xss')
        self.check(prefix + 'fail(o, req.query.html); res.send(o.html);')

    def test_thrown_fresh_object_keeps_alias_in_handler(self):
        self.check('function fail(v) { throw {html: v}; } try { fail(req.query.html); } '
                   'catch (error) { const alias = error; res.send(alias.html); }', 'xss')
        self.check('function fail(v) { throw {html: "safe", other: v}; } '
                   'try { fail(req.query.html); } catch (error) { res.send(error.html); }')

    def test_returned_object_observes_finalizer_mutation(self):
        self.check('function read(v) { const o={html:v}; try { return o; } '
                   'finally { o.html="safe"; } } res.send(read(req.query.html).html);')
        self.check('function read(v) { const o={html:"safe"}; try { return o; } '
                   'finally { o.html=v; } } res.send(read(req.query.html).html);', 'xss')

    def test_logical_and_conditional_returning_paths_survive_throw(self):
        prefix = 'function fail(){throw "failure";} '
        self.check(prefix + 'res.send(flag ? fail() : req.query.html);', 'xss')
        self.check(prefix + 'res.send(flag ? req.query.html : fail());', 'xss')
        self.check(prefix + 'try { res.send(flag ? fail() : fail()); } catch(e) {}')
        self.check(prefix + 'res.send(req.query.html || fail());', 'xss')

    def test_finalizer_break_discards_return_but_keeps_write(self):
        self.check('function read(v) { let out="safe"; while(flag) { try { return "safe"; } '
                   'finally { out=v; break; } } return out; } res.send(read(req.query.html));', 'xss')

    def test_async_throw_is_not_a_synchronous_throw(self):
        self.check('async function fail(){throw "failure";} fail(); res.send(req.query.html);', 'xss')
        self.check('async function fail(){throw req.query.html;} '
                   'try { fail(); } catch(e) { res.send(e); }')
        self.check('async function fail(){throw req.query.html;} '
                   'try { await fail(); } catch(e) { res.send(e); }', 'xss')

    def test_async_throw_retains_pre_rejection_writes(self):
        self.check('let out="safe"; async function fail(){out=req.query.html;throw "failure";} '
                   'fail(); res.send(out);', 'xss')

    def test_async_default_rejection_does_not_stop_caller(self):
        self.check('function fail(){throw "failure";} async function f(x=fail()){} '
                   'f(); res.send(req.query.html);', 'xss')

    def test_async_rejected_heap_write_is_visible_before_await(self):
        self.check('const o={}; async function fail(v){o.html=v;throw "failure";} '
                   'fail(req.query.html); res.send(o.html);', 'xss')

    def test_async_arrow_body_is_not_a_synchronous_throw(self):
        self.check('const fail=async () => {throw "failure";}; fail(); res.send(req.query.html);', 'xss')
        self.check('const fail=async () => {throw req.query.html;}; '
                   'try { await fail(); } catch(e) { res.send(e); }', 'xss')

    def test_early_return_and_throw_keep_separate_caller_stores(self):
        self.check('let out="safe"; function f(v){if(flag){out=v;throw "bad";} out="safe";} '
                   'try { f(req.query.html); res.send(out); } catch(e){res.send(out);}', 'xss')

    def test_argument_throw_keeps_prior_argument_effects_only(self):
        self.check('let out="safe"; function put(){out=req.query.html;} function fail(){throw "bad";} '
                   'function clear(){out="safe";} try { external(put(),fail(),clear()); } '
                   'catch(e){res.send(out);}', 'xss')

    def test_nested_finalizer_throw_value_replaces_exception(self):
        self.check('function f(v){try{throw "safe";}finally{throw v;}} '
                   'try{f(req.query.html);}catch(e){res.send(e);}', 'xss')
        self.check('function f(v){try{throw v;}finally{throw "safe";}} '
                   'try{f(req.query.html);}catch(e){res.send(e);}')

    def test_generator_creation_does_not_run_throwing_body(self):
        self.check('function* g(){throw "failure";} g(); res.send(req.query.html);', 'xss')

    def test_cross_module_exception_and_normal_completions(self):
        for suffix, helper, caller in (
            ('mjs', 'export function fail(v){throw v;}',
             'import {fail} from "./helper.mjs";'),
            ('cjs', 'exports.fail=function(v){throw v;};',
             'const {fail}=require("./helper.cjs");'),
        ):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory(prefix='ubs-completion-modules-') as tmp:
                root = Path(tmp)
                lib, app = root / ('helper.' + suffix), root / ('app.' + suffix)
                lib.write_text(helper, encoding='utf-8')
                app.write_text(caller + 'try { fail(req.query.html); } catch(e){res.send(e);}', encoding='utf-8')
                findings = list(taint_js.run(RunContext(lang='javascript', files=[lib, app])))
                self.assertEqual([(Path(f['path']).name, f['rule']) for f in findings],
                                 [(app.name, 'javascript.taint.xss')], findings)

    def test_catch_binding_is_captured_by_nested_helper(self):
        self.check('try { throw req.query.html; } catch (error) { '
                   'function read() { return error; } res.send(read()); }', 'xss')
        self.check('const error = req.query.html; try { throw "safe"; } catch (error) { '
                   'function read() { return error; } res.send(read()); }')

    def test_nested_catch_bindings_have_distinct_cells(self):
        source = ('try { throw req.query.html; } catch (error) { '
                  'function read() { return error; } '
                  'try { throw "safe"; } catch (error) { res.send(read()); } }')
        self.check(source, 'xss')

    def test_catch_object_pattern_projects_only_bound_properties(self):
        self.check('try { throw {html:"safe", other:req.query.html}; } '
                   'catch ({html}) { res.send(html); }')
        self.check('try { throw {html:req.query.html, other:"safe"}; } '
                   'catch ({html:value}) { res.send(value); }', 'xss')

    def test_catch_nested_pattern_preserves_object_identity(self):
        self.check('try { throw {payload:{html:req.query.html}, other:"safe"}; } '
                   'catch ({payload:value}) { const alias=value; alias.html="safe"; res.send(value.html); }')
        self.check('try { throw {payload:{html:req.query.html}, other:"safe"}; } '
                   'catch ({payload:{html:value}}) { res.send(value); }', 'xss')

    def test_catch_array_pattern_projects_slots_and_rest(self):
        self.check('try { throw ["safe", req.query.html]; } catch ([value]) { res.send(value); }')
        self.check('try { throw ["safe", req.query.html]; } catch ([,value]) { res.send(value); }', 'xss')
        self.check('try { throw [req.query.html,"safe"]; } catch ([first,...rest]) { res.send(rest[0]); }')

    def test_catch_object_rest_excludes_bound_properties(self):
        self.check('try { throw {html:req.query.html, other:"safe"}; } '
                   'catch ({html,...rest}) { res.send(rest.other); }')
        self.check('try { throw {html:"safe", other:req.query.html}; } '
                   'catch ({html,...rest}) { res.send(rest.other); }', 'xss')

    def test_missing_catch_property_evaluates_default_source(self):
        self.check('try { throw {}; } catch ({html=req.query.html}) { res.send(html); }', 'xss')
        self.check('try { throw {payload:{}}; } catch ({payload:{html=req.query.html}}) { res.send(html); }', 'xss')

    def test_throwing_catch_default_reaches_outer_handler_and_finalizer(self):
        self.check('let out="safe"; function fail(){throw req.query.html;} '
                   'try { try { throw {}; } catch ({html=fail()}) { out="unreachable"; } '
                   'finally { out=req.query.other; } } catch (error) { res.send(error); res.send(out); }',
                   'xss', 'xss')

    def test_unknown_catch_default_does_not_prove_cleanup(self):
        self.check('let out=req.query.html; function clear(){out="safe";return "safe";} '
                   'try { throw req.body; } catch ({html=clear()}) {} res.send(out);', 'xss')

    def test_catch_computed_keys_retain_side_effect_order(self):
        self.check('let out="safe"; function key(){out=req.query.html;return "html";} '
                   'try { throw {html:"safe"}; } catch ({[key()]:value}) { res.send(out); }', 'xss')

    def test_catch_pattern_boundaries_restore_same_named_outer_bindings(self):
        self.check('const html=req.query.html; try { throw {html:"safe"}; } '
                   'catch ({html}) { res.send(html); } res.send(html);', 'xss')

    def test_fixed_completions_agree_with_native_node(self):
        # Only fixed test fixtures are executed. The analyzer never executes
        # source, loads dependencies, or invokes a scanned helper.
        import shutil
        node = shutil.which('node')
        if node is None:
            self.skipTest('Node is required for independent semantics controls')
        cases = [
            'function read(){try{return req.query.html;}finally{return "safe";}}res.send(read());',
            'function fail(v){throw v;}try{fail(req.query.html);}catch(e){res.send(e);}',
            'function fail(){throw "stop";}res.send(req.query.html,fail());',
            'const o={};function fail(v){o.html=v;throw "stop";}try{fail(req.query.html);}catch(e){res.send(o.html);}',
            'function read(v){const o={html:v};try{return o;}finally{o.html="safe";}}res.send(read(req.query.html).html);',
            'let out=req.query.html;function clear(){out="safe";return "";}out+=clear();res.send(out);',
            'function clean(v){return "safe";}function id(v){return v;}function swap(){clean=id;return req.query.html;}res.send(clean(swap()));res.send(clean(req.query.html));',
            'function fail(){throw "stop";}try{if(fail())res.send(req.query.html);}catch(e){}',
            'function fail(){throw "stop";}try{while(fail())res.send(req.query.html);}catch(e){}',
            'function fail(){throw "stop";}try{for(fail();false;)res.send(req.query.html);}catch(e){}',
            'function fail(){throw "stop";}try{switch(fail()){case 1:res.send(req.query.html);}}catch(e){}',
            'let out="safe";function fail(){out=req.query.html;throw "stop";}function f(x=fail()){out="safe";}try{f();}catch(e){res.send(out);}',
            'try{throw req.query.html;}catch(e){function read(){return e;}res.send(read());}',
            'const e=req.query.html;try{throw "safe";}catch(e){function read(){return e;}res.send(read());}',
            'try{throw {html:"safe",other:req.query.html};}catch({html}){res.send(html);}',
            'try{throw {html:req.query.html,other:"safe"};}catch({html,...rest}){res.send(rest.other);}',
            'try{throw [req.query.html,"safe"];}catch([first,...rest]){res.send(rest[0]);}',
            'try{throw {};}catch({html=req.query.html}){res.send(html);}',
            'try{throw {payload:{html:req.query.html}};}catch({payload:value}){const alias=value;alias.html="safe";res.send(value.html);}',
            'function fail(){throw req.query.html;}try{try{throw {};}catch({html=fail()}){res.send("safe");}}catch(e){res.send(e);}',
        ]
        prefix = ('const req={query:{html:"UBS_UNTRUSTED"}};const seen=[];'
                  'const res={send(...args){if(args.some(x=>String(x).includes("UBS_UNTRUSTED")))seen.push(1);}};')
        for number, source in enumerate(cases):
            with self.subTest(case=number):
                native = subprocess.run([node, '-e', prefix + 'try{' + source + '}catch(e){};console.log(JSON.stringify(seen));'],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(native.returncode, 0, native.stderr)
                self.assertEqual(len(scan(source)), len(json.loads(native.stdout)), (source, native.stdout))


@unittest.skipUnless(os.environ.get('UBS_TAINT_E2E') == '1', 'set UBS_TAINT_E2E=1 for real scanner checks')
class CallCompletionScannerTests(unittest.TestCase):
    def test_actual_scanner_completion_and_ordering(self):
        cases = [
            ('before-clear', 'let out=req.query.html; function clear(){out="safe";return "";} res.send(out+clear());', {'xss'}),
            ('after-clear', 'let out=req.query.html; function clear(){out="safe";return "";} res.send(clear()+out);', set()),
            ('final-return', 'function read(){try{return req.query.html;}finally{return "safe";}} res.send(read());', set()),
            ('thrown-write', 'let out="safe";function put(v){out=v;throw Error();}try{put(req.query.html);}catch(e){res.send(out);}', {'xss'}),
            ('no-continuation', 'let out="safe";function put(v){out=v;throw Error();}put(req.query.html);res.send(out);', set()),
            ('thrown-value', 'function fail(v){throw v;}try{fail(req.query.html);}catch(e){res.send(e);}', {'xss'}),
            ('thrown-object', 'function fail(v){throw {html:v};}try{fail(req.query.html);}catch(e){res.send(e.html);}', {'xss'}),
            ('thrown-default', 'let out="safe";function fail(){out=req.query.html;throw "bad";}function f(v=fail()){out="safe";}try{f();}catch(e){res.send(out);}', {'xss'}),
            ('normal-call', 'function f(){return "safe";}try{f();}catch(e){res.send(req.query.html);}', set()),
            ('async-rejection', 'async function fail(){throw "bad";}fail();res.send(req.query.html);', {'xss'}),
            ('generator-create', 'function* f(){throw "bad";}f();res.send(req.query.html);', {'xss'}),
            ('callee-snapshot', 'function clean(v){return "safe";}function id(v){return v;}function swap(){clean=id;return req.query.html;}res.send(clean(swap()));res.send(clean(req.query.html));', {'xss'}),
            ('catch-closure', 'try{throw req.query.html;}catch(e){function read(){return e;}res.send(read());}', {'xss'}),
            ('catch-field-clean', 'try{throw {html:"safe",other:req.query.html};}catch({html}){res.send(html);}', set()),
            ('catch-default-source', 'try{throw {};}catch({html=req.query.html}){res.send(html);}', {'xss'}),
            ('catch-default-throw', 'function fail(){throw req.query.html;}try{try{throw {};}catch({html=fail()}){res.send("safe");}}catch(e){res.send(e);}', {'xss'}),
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
                (artifacts / 'result.json').write_text(json.dumps(report, indent=2))
                channels = [(report.get('findings', []), 'rule_id', 'file')]
                channels.extend((scanner['findings'], 'rule', 'path') for scanner in report['scanners']
                                if scanner['language'] == 'js')
                self.assertGreaterEqual(len(channels), 2, report)
                for records, rule_key, path_key in channels:
                    rules = Counter()
                    for record in records:
                        rule = record[rule_key]
                        if not rule.startswith(('javascript.taint.', 'js.taint.')):
                            continue
                        rules[rule.rsplit('.', 1)[-1]] += 1
                        location = Path(record[path_key])
                        location = location if location.is_absolute() else Path(tmp) / location
                        self.assertEqual(location.resolve(), target.resolve(), record)
                        self.assertGreater(record['line'], 0, record)
                        self.assertGreater(record['col'], 0, record)
                        self.assertEqual(record['severity'], 'critical', record)
                        self.assertFalse(record['suppressed'], record)
                    self.assertEqual(rules, Counter(expected), (source, report))
                print('JS_COMPLETION_E2E_PASS', name, sorted(expected), flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
