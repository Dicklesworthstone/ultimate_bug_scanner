"""Selected, static CommonJS interfaces and conservative unsupported controls."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_taint_js_modules as module_tests
from ubs_core import js_scan
from ubs_core.js_modules import ModuleGraph


class CommonJSTaintTests(unittest.TestCase):
    write = module_tests.ModuleTaintTests.write
    scan = module_tests.ModuleTaintTests.scan
    assert_report_findings = module_tests.ModuleTaintTests.assert_report_findings

    def pair(self, library, caller, *expected):
        return self.scan({'lib.cjs': library, 'app.cjs': caller}, *expected)

    def test_namespace_source_function(self):
        self.pair('exports.read = function() { return req.query.html; };',
                  'const api = require("./lib.cjs"); res.send(api.read());', ('app.cjs', 'xss'))

    def test_mutating_export_through_an_alias_invalidates_clean_callable(self):
        self.pair('exports.clean = x => "hello";',
                  'const api=require("./lib.cjs"); const alias=api; '
                  'alias.clean=external; res.send(api.clean(req.query.html));', ('app.cjs', 'xss'))

    def test_object_export_alias_has_the_same_mutable_identity(self):
        self.pair('module.exports = {clean: x => "hello"};',
                  'const api=require("./lib.cjs"); const alias=api; '
                  'alias.clean=external; res.send(api.clean(req.query.html));', ('app.cjs', 'xss'))

    def test_borrowed_export_mutation_invalidates_clean_callable(self):
        self.pair('exports.clean = x => "hello";',
                  'const api=require("./lib.cjs"); function change(obj){obj.clean=external;} '
                  'change(api); res.send(api.clean(req.query.html));', ('app.cjs', 'xss'))

    def test_object_assign_export_mutation_invalidates_clean_callable(self):
        self.pair('exports.clean = x => "hello";',
                  'const api=require("./lib.cjs"); const alias=api; '
                  'Object.assign(alias,{clean: external}); res.send(api.clean(req.query.html));', ('app.cjs', 'xss'))

    def test_alias_write_is_visible_through_original_export_name(self):
        self.pair('exports.html = "hello";',
                  'const api=require("./lib.cjs"); const alias=api; '
                  'alias.html=req.query.html; res.send(api.html);', ('app.cjs', 'xss'))

    def test_alias_clean_overwrite_reaches_original_export_name(self):
        self.pair('exports.html = req.query.html;',
                  'const api=require("./lib.cjs"); const alias=api; alias.html="hello"; res.send(api.html);')

    def test_conditional_alias_cleanup_does_not_remove_the_dirty_path(self):
        self.pair('exports.html = req.query.html;',
                  'const api=require("./lib.cjs"); const alias=api; '
                  'if(flag){alias.html="hello";} res.send(api.html);', ('app.cjs', 'xss'))

    def test_unknown_key_write_cannot_leave_a_clean_callable_summary(self):
        self.pair('exports.clean = x => "hello";',
                  'const api=require("./lib.cjs"); const alias=api; '
                  'alias[key]=external; res.send(api.clean(req.query.html));', ('app.cjs', 'xss'))

    def test_unrelated_export_write_does_not_invalidate_clean_callable(self):
        self.pair('exports.clean = x => "hello"; exports.other="hello";',
                  'const api=require("./lib.cjs"); const alias=api; '
                  'alias.other=req.query.html; res.send(api.clean(req.query.html));')

    def test_require_scalar_snapshot_survives_later_export_cleanup(self):
        self.pair('exports.html = req.query.html;',
                  'const {html}=require("./lib.cjs"); const api=require("./lib.cjs"); '
                  'api.html="hello"; res.send(html);', ('app.cjs', 'xss'))

    def test_require_scalar_snapshot_is_not_retroactively_tainted(self):
        self.pair('exports.html = "hello";',
                  'const {html}=require("./lib.cjs"); const api=require("./lib.cjs"); '
                  'api.html=req.query.html; res.send(html);')

    def test_later_require_scalar_reads_the_current_shared_property(self):
        self.pair('exports.html = "hello";',
                  'const api=require("./lib.cjs"); api.html=req.query.html; '
                  'const {html}=require("./lib.cjs"); res.send(html);', ('app.cjs', 'xss'))

    def test_require_function_snapshot_survives_export_replacement(self):
        self.pair('exports.clean = x => "hello";',
                  'const {clean}=require("./lib.cjs"); const api=require("./lib.cjs"); '
                  'api.clean=external; res.send(clean(req.query.html));')

    def test_later_require_cannot_reuse_replaced_function(self):
        self.pair('exports.clean = x => "hello";',
                  'const api=require("./lib.cjs"); api.clean=external; '
                  'const {clean}=require("./lib.cjs"); res.send(clean(req.query.html));', ('app.cjs', 'xss'))

    def test_closure_observes_mutated_namespace_callable(self):
        self.pair('exports.clean = x => "hello";',
                  'const api=require("./lib.cjs"); const alias=api; alias.clean=external; '
                  'function render(){res.send(api.clean(req.query.html));}', ('app.cjs', 'xss'))

    def test_closure_observes_mutated_namespace_field(self):
        self.pair('exports.html = "hello";',
                  'const api=require("./lib.cjs"); const alias=api; alias.html=req.query.html; '
                  'function render(){res.send(api.html);}', ('app.cjs', 'xss'))

    def test_closure_observes_cleaned_namespace_field(self):
        self.pair('exports.html = req.query.html;',
                  'const api=require("./lib.cjs"); const alias=api; alias.html="hello"; '
                  'function render(){res.send(api.html);}')

    def test_closure_retains_field_precision(self):
        self.pair('exports.html = "hello"; exports.other=req.query.html;',
                  'const api=require("./lib.cjs"); function render(){res.send(api.html);}')

    def test_scalar_operand_is_read_before_export_cleanup_call(self):
        self.pair('exports.html = req.query.html;',
                  'const api=require("./lib.cjs"); function clear(obj){obj.html="hello"; return "";} '
                  'res.send(api.html + clear(api));', ('app.cjs', 'xss'))

    def test_export_cleanup_precedes_later_scalar_operand(self):
        self.pair('exports.html = req.query.html;',
                  'const api=require("./lib.cjs"); function clear(obj){obj.html="hello"; return "";} '
                  'res.send(clear(api) + api.html);')

    def test_default_function_value(self):
        self.pair('module.exports = function() { return req.query.html; };',
                  'const read = require("./lib.cjs"); res.send(read());', ('app.cjs', 'xss'))

    def test_default_arrow_value(self):
        self.pair('module.exports = () => req.query.html;',
                  'const read = require("./lib.cjs"); res.send(read());', ('app.cjs', 'xss'))

    def test_named_require_alias(self):
        self.pair('exports.read = () => req.query.html;',
                  'const {read: get} = require("./lib.cjs"); res.send(get());', ('app.cjs', 'xss'))

    def test_static_member_require(self):
        self.pair('module.exports.read = () => req.query.html;',
                  'const get = require("./lib.cjs").read; res.send(get());', ('app.cjs', 'xss'))

    def test_literal_bracket_export(self):
        self.pair('exports["read"] = () => req.query.html;',
                  'const {read} = require("./lib.cjs"); res.send(read());', ('app.cjs', 'xss'))

    def test_source_scalar(self):
        self.pair('exports.html = req.query.html;',
                  'const {html} = require("./lib.cjs"); res.send(html);', ('app.cjs', 'xss'))

    def test_default_scalar(self):
        self.pair('module.exports = req.query.html;',
                  'const html = require("./lib.cjs"); res.send(html);', ('app.cjs', 'xss'))

    def test_object_export_shorthand_functions(self):
        self.pair('function read(){ return req.query.html; } module.exports = {read};',
                  'const {read} = require("./lib.cjs"); res.send(read());', ('app.cjs', 'xss'))

    def test_object_export_inline_functions(self):
        self.pair('module.exports = {read: () => req.query.html};',
                  'const {read} = require("./lib.cjs"); res.send(read());', ('app.cjs', 'xss'))

    def test_object_export_clean_field_is_not_contaminated(self):
        self.pair('module.exports = {raw: req.query.html, clean: "safe"};',
                  'const api = require("./lib.cjs"); res.send(api.clean);')
        self.pair('module.exports = {raw: req.query.html, clean: "safe"};',
                  'const api = require("./lib.cjs"); res.send(api.raw);', ('app.cjs', 'xss'))

    def test_namespace_as_a_value_contains_its_exported_data(self):
        self.pair('exports.raw = req.query.html;',
                  'const api = require("./lib.cjs"); res.send(api);', ('app.cjs', 'xss'))

    def test_unused_argument_does_not_taint_constant_result(self):
        self.pair('exports.clean = x => "safe";',
                  'const {clean} = require("./lib.cjs"); res.send(clean(req.query.html));')

    def test_parameter_flows_to_exported_sink(self):
        self.pair('exports.send = function(value) { res.send(value); };',
                  'const {send} = require("./lib.cjs"); send(req.query.html);', ('lib.cjs', 'xss'))

    def test_clean_call_of_exported_sink(self):
        self.pair('exports.send = function(value) { res.send(value); };',
                  'const {send} = require("./lib.cjs"); send("safe");')

    def test_export_snapshot_does_not_follow_later_clean_reassignment(self):
        self.pair('let f = x => x; exports.f = f; f = x => "safe";',
                  'const {f} = require("./lib.cjs"); res.send(f(req.query.html));', ('app.cjs', 'xss'))

    def test_clean_export_snapshot_does_not_follow_later_unsafe_reassignment(self):
        self.pair('let f = x => "safe"; exports.f = f; f = x => x;',
                  'const {f} = require("./lib.cjs"); res.send(f(req.query.html));')

    def test_later_static_export_write_replaces_the_snapshot(self):
        self.pair('exports.f = x => "safe"; exports.f = x => x;',
                  'const {f} = require("./lib.cjs"); res.send(f(req.query.html));', ('app.cjs', 'xss'))
        self.pair('exports.f = x => x; exports.f = x => "safe";',
                  'const {f} = require("./lib.cjs"); res.send(f(req.query.html));')

    def test_sanitizer_wrapper_keeps_its_domain(self):
        self.pair('exports.escape = x => DOMPurify.sanitize(x);',
                  'const {escape} = require("./lib.cjs"); res.send(escape(req.query.html)); eval(escape(req.query.html));',
                  ('app.cjs', 'eval'))

    def test_unselected_relative_sanitizer_does_not_prove_clean(self):
        self.scan({'app.cjs': 'const escapeHtml = require("./missing.cjs"); res.send(escapeHtml(req.query.html));'},
                  ('app.cjs', 'xss'))

    def test_shadowed_require_does_not_load_selected_clean_helper(self):
        self.pair('module.exports = x => "safe";',
                  'const require = name => (x => x); const escapeHtml = require("./lib.cjs");'
                  'res.send(escapeHtml(req.query.html));', ('app.cjs', 'xss'))

    def test_dynamic_export_mutation_invalidates_clean_interface(self):
        self.pair('exports.f = x => "safe"; exports[key] = external;',
                  'const {f} = require("./lib.cjs"); res.send(f(req.query.html));', ('app.cjs', 'xss'))

    def test_export_alias_escape_invalidates_clean_interface(self):
        self.pair('exports.f = x => "safe"; change(exports);',
                  'const {f} = require("./lib.cjs"); res.send(f(req.query.html));', ('app.cjs', 'xss'))

    def test_conditional_export_write_does_not_leave_stale_clean_summary(self):
        self.pair('exports.f = x => "safe"; if (flag) { exports.f = x => x; }',
                  'const {f} = require("./lib.cjs"); res.send(f(req.query.html));', ('app.cjs', 'xss'))

    def test_replaced_imported_property_does_not_use_old_clean_summary(self):
        self.pair('exports.f = x => "safe";',
                  'const api = require("./lib.cjs"); api.f = x => x; res.send(api.f(req.query.html));',
                  ('app.cjs', 'xss'))

    def test_package_require_is_not_resolved_by_basename(self):
        self.pair('exports.f = x => "safe";',
                  'const {f} = require("lib.cjs"); res.send(f(req.query.html));', ('app.cjs', 'xss'))

    def test_unselected_file_is_not_discovered(self):
        self.scan({'lib.cjs': 'module.exports = () => req.query.html;',
                   'app.cjs': 'const read = require("./lib.cjs"); res.send(read());'}, select=['app.cjs'])

    def test_exported_helper_preserves_borrowed_heap_mutations(self):
        self.pair('exports.set = function(b, value) { b.html = value; };',
                  'const {set} = require("./lib.cjs"); const b = {}; set(b, req.query.html); res.send(b.html);',
                  ('app.cjs', 'xss'))

    def test_exported_helper_preserves_clean_overwrites(self):
        self.pair('exports.clear = function(b) { b.html = "safe"; };',
                  'const {clear} = require("./lib.cjs"); const b = {html:req.query.html}; clear(b); res.send(b.html);')

    def test_factory_results_keep_distinct_identities(self):
        self.pair('exports.make = function(x) { return {html:x}; };',
                  'const {make} = require("./lib.cjs"); const a = make(req.query.html);'
                  'const b = make("safe"); res.send(b.html); res.send(a.html);', ('app.cjs', 'xss'))

    def test_same_named_module_locals_are_separate(self):
        self.pair('const html = req.query.html; exports.clean = () => "safe";',
                  'const {clean} = require("./lib.cjs"); const html = "safe"; res.send(html); res.send(clean());')

    def test_multiline_import_and_export_preserve_coordinates(self):
        found = self.pair('exports.read = function() {\n return req.query.html;\n};',
                          'const {\n read\n} = require("./lib.cjs");\n  res.send(read());', ('app.cjs', 'xss'))
        self.assertEqual((found[0]['line'], found[0]['col']), (4, 3))

    def test_require_edges_participate_in_cache_components(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.write(Path(tmp), {'lib.cjs':'exports.read = () => "safe";',
                'app.cjs':'const {read}=require("./lib.cjs"); res.send(read());', 'other.js':'const x=1;'})
            graph = ModuleGraph(paths)
            components = {frozenset(module.path.name for module in group) for group in graph.components()}
            self.assertEqual(components, {frozenset(('lib.cjs', 'app.cjs')), frozenset(('other.js',))})

    def test_extensionless_require_uses_js_before_index_and_not_cjs(self):
        self.scan({'lib.js': 'exports.read=()=>req.query.html;',
                   'lib.cjs': 'exports.read=()=>"safe";',
                   'lib/index.js': 'exports.read=()=>"safe";',
                   'app.cjs': 'const {read}=require("./lib");res.send(read());'}, ('app.cjs','xss'))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self.write(root, {'lib.cjs': 'module.exports=x=>"safe";',
                                      'app.cjs': 'const f=require("./lib");res.send(f(req.query.html));'})
            graph = ModuleGraph(paths)
            self.assertIsNone(graph.resolve(graph.modules[paths[1]], './lib'))
        self.scan({'lib/index.js': 'exports.read=()=>req.query.html;',
                   'app.cjs': 'const {read}=require("./lib");res.send(read());'}, ('app.cjs','xss'))

    def test_require_cycle_does_not_use_eventual_clean_interface(self):
        sources = {'a.cjs': 'exports.f=x=>"safe";const b=require("./b.cjs");',
                   'b.cjs': 'const {f}=require("./a.cjs");exports.value=f(req.query.html);',
                   'app.cjs': 'const {f}=require("./a.cjs");res.send(f(req.query.html));'}
        self.scan(sources, ('app.cjs','xss'))
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.write(Path(tmp), sources)
            graph = ModuleGraph(paths)
            self.assertIsNone(graph.exported(graph.modules[paths[0]], 'f'))
            self.assertIsNone(graph.exported(graph.modules[paths[1]], 'value'))

    def test_unused_require_still_forms_a_cycle(self):
        self.scan({'a.cjs': 'exports.f=x=>"safe";require("./b.cjs");',
                   'b.cjs': 'require("./a.cjs");exports.value="safe";',
                   'app.cjs': 'const {f}=require("./a.cjs");res.send(f(req.query.html));'}, ('app.cjs','xss'))

    def test_deep_commonjs_cycle_detection_is_iterative(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.write(Path(tmp), {
                f'm{i}.cjs': f'const next=require("./m{(i+1)%1200}.cjs");exports.f=x=>"safe";'
                for i in range(1200)})
            graph = ModuleGraph(paths)
            self.assertTrue(all(module.commonjs == 'unknown' for module in graph.modules.values()))

    def test_commonjs_cache_invalidates_exporter_and_caller(self):
        with tempfile.TemporaryDirectory(prefix='ubs-cjs-cache-') as tmp:
            root = Path(tmp).resolve()
            paths = self.write(root, {'lib.cjs':'exports.f=x=>"safe";',
                'app.cjs':'const {f}=require("./lib.cjs");res.send(f(req.query.html));',
                'other.js':'const answer=42;'})
            listing, sink, stats = root/'files', root/'sink', root/'stats'
            def scan():
                listing.write_bytes(b'\0'.join(os.fsencode(path) for path in paths)+b'\0')
                status = js_scan.main(['--files-from',str(listing),'--sink',str(sink),'--project-dir',str(root)])
                records = [json.loads(line) for line in sink.read_text().splitlines()]
                self.assertEqual(status,int(any(r['severity']=='critical' for r in records)),records)
                return [r for r in records if r['rule'].startswith('javascript.taint.')], json.loads(stats.read_text())
            with mock.patch.dict(os.environ,{'UBS_CACHE_DIR':str(root/'cache'), 'UBS_NO_CACHE':'0',
                                             'UBS_CACHE_FILE':str(stats)}):
                self.assertEqual(scan()[0],[])
                self.assertEqual(scan()[1]['hits'],3)
                paths[0].write_text('exports.f=x=>x;')
                found, profile = scan()
                self.assertEqual([f['rule'] for f in found],['javascript.taint.xss'])
                self.assertEqual((profile['hits'],profile['misses']),(1,2))
                self.assertEqual(scan()[1]['hits'],3)
                paths[1].write_text('const {f}=require("./lib.cjs");res.send(f("safe"));')
                found, profile = scan()
                self.assertEqual(found,[])
                self.assertEqual((profile['hits'],profile['misses']),(1,2))

    def test_commonjs_parallel_cli_preserves_connected_inputs(self):
        with tempfile.TemporaryDirectory(prefix='ubs-cjs-jobs-') as tmp:
            root = Path(tmp).resolve()
            paths = self.write(root, {'lib.cjs':'exports.send=x=>res.send(x);',
                'app.cjs':'const {send}=require("./lib.cjs");send(req.query.html);',
                'other.js':'const answer=42;'})
            listing = root/'files'
            listing.write_bytes(b'\0'.join(os.fsencode(path) for path in paths)+b'\0')
            results = []
            for jobs in (1,4):
                result = subprocess.run([sys.executable,'-m','ubs_core','taint','--lang','javascript',
                                         '--files-from',str(listing),'--jobs',str(jobs)],cwd=tmp,
                                        capture_output=True,text=True,timeout=30,
                                        env={**os.environ,'PYTHONPATH':str(ROOT/'modules/helpers')})
                self.assertIn(result.returncode,(0,1),result.stderr)
                records = [json.loads(line) for line in result.stdout.splitlines()]
                self.assertEqual([(Path(r['path']).name,r['rule']) for r in records],
                                 [('lib.cjs','javascript.taint.xss')])
                results.append(records)
            self.assertEqual(results[0],results[1])

    @unittest.skipUnless(shutil.which('node'), 'requires Node for independent fixed-source controls')
    def test_static_interfaces_agree_with_node_execution(self):
        cases = [
            ('exports.read=()=>req.query.html;', 'const api=require("./lib.cjs");res.send(api.read());', True),
            ('module.exports=()=>req.query.html;', 'const read=require("./lib.cjs");res.send(read());', True),
            ('exports.read=x=>"safe";', 'const {read}=require("./lib.cjs");res.send(read(req.query.html));', False),
            ('exports.read=x=>x;', 'const {read:get}=require("./lib.cjs");res.send(get(req.query.html));', True),
            ('let f=x=>x;exports.f=f;f=x=>"safe";', 'const {f}=require("./lib.cjs");res.send(f(req.query.html));', True),
            ('let f=x=>"safe";exports.f=f;f=x=>x;', 'const {f}=require("./lib.cjs");res.send(f(req.query.html));', False),
            ('module.exports={raw:req.query.html,clean:"safe"};', 'const api=require("./lib.cjs");res.send(api.clean);', False),
            ('exports.make=x=>({html:x});', 'const {make}=require("./lib.cjs");res.send(make(req.query.html).html);', True),
            ('exports.clean=x=>"safe";', 'const api=require("./lib.cjs");const alias=api;alias.clean=external;res.send(api.clean(req.query.html));', True),
            ('exports.html="safe";', 'const api=require("./lib.cjs");const alias=api;alias.html=req.query.html;res.send(api.html);', True),
            ('exports.html=req.query.html;', 'const api=require("./lib.cjs");const alias=api;alias.html="safe";res.send(api.html);', False),
            ('exports.html="safe";', 'const {html}=require("./lib.cjs");const api=require("./lib.cjs");api.html=req.query.html;res.send(html);', False),
            ('exports.html=req.query.html;', 'const {html}=require("./lib.cjs");const api=require("./lib.cjs");api.html="safe";res.send(html);', True),
            ('exports.clean=x=>"safe";', 'const {clean}=require("./lib.cjs");const api=require("./lib.cjs");api.clean=external;res.send(clean(req.query.html));', False),
            ('exports.clean=x=>"safe";', 'const api=require("./lib.cjs");api.clean=external;const {clean}=require("./lib.cjs");res.send(clean(req.query.html));', True),
            ('exports.clean=x=>"safe";', 'const api=require("./lib.cjs");function change(o){o.clean=external;}change(api);res.send(api.clean(req.query.html));', True),
        ]
        program = '''const out=[];global.req={query:{html:"CONTROL_TAINT"}};
global.external=value=>value;
global.res={send(value){out.push(JSON.stringify(value));}};
require(process.argv[1]);console.log(JSON.stringify(out));'''
        for library, caller, expected in cases:
            with self.subTest(library=library), tempfile.TemporaryDirectory(prefix='ubs-cjs-node-') as tmp:
                root = Path(tmp)
                self.write(root, {'lib.cjs': library, 'app.cjs': caller})
                result = subprocess.run(['node', '-e', program, str(root / 'app.cjs')],
                                        capture_output=True, text=True, timeout=10, check=True)
                self.assertEqual(any('CONTROL_TAINT' in value for value in json.loads(result.stdout)), expected)
                self.pair(library, caller, *((('app.cjs', 'xss'),) if expected else ()))

    @unittest.skipUnless(shutil.which('ast-grep'), 'requires ast-grep for the actual meta-runner')
    def test_meta_runner_static_commonjs_interfaces(self):
        cases = [
            ('source', 'exports.read=()=>req.query.html;', 'const {read}=require("./lib.cjs");res.send(read());', ('app.cjs','xss')),
            ('sink', 'exports.send=x=>res.send(x);', 'const {send}=require("./lib.cjs");send(req.query.html);', ('lib.cjs','xss')),
            ('clean', 'module.exports=x=>"safe";', 'const f=require("./lib.cjs");res.send(f(req.query.html));', None),
            ('heap', 'exports.set=(b,x)=>{b.html=x;};', 'const {set}=require("./lib.cjs");const b={};set(b,req.query.html);res.send(b.html);', ('app.cjs','xss')),
            ('alias-function', 'exports.clean=x=>"safe";', 'const api=require("./lib.cjs");const alias=api;alias.clean=external;res.send(api.clean(req.query.html));', ('app.cjs','xss')),
            ('alias-field', 'exports.html="safe";', 'const api=require("./lib.cjs");const alias=api;alias.html=req.query.html;res.send(api.html);', ('app.cjs','xss')),
            ('snapshot-clean', 'exports.html="safe";', 'const {html}=require("./lib.cjs");const api=require("./lib.cjs");api.html=req.query.html;res.send(html);', None),
            ('snapshot-dirty', 'exports.html=req.query.html;', 'const {html}=require("./lib.cjs");const api=require("./lib.cjs");api.html="safe";res.send(html);', ('app.cjs','xss')),
        ]
        for name, library, caller, expected in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix='ubs-cjs-e2e-') as tmp:
                root = Path(tmp).resolve()
                self.write(root, {'lib.cjs':library, 'app.cjs':caller})
                result = subprocess.run([str(ROOT / 'ubs'), str(root), '--only=js', '--format=json', '--ci'],
                                        capture_output=True, text=True, cwd=tmp, timeout=120,
                                        env={**os.environ,'UBS_NO_AUTO_UPDATE':'1','UBS_NO_CACHE':'1'})
                self.assertIn(result.returncode, (0, 1), (result.stdout, result.stderr))
                artifact = ROOT/'test-suite/artifacts/javascript-commonjs'/name
                artifact.mkdir(parents=True, exist_ok=True)
                (artifact/'result.json').write_text(result.stdout)
                (artifact/'stderr.log').write_text(result.stderr)
                self.assert_report_findings(json.loads(result.stdout), root, expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)