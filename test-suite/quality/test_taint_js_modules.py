"""D6 selected ES-module summaries, source coordinates and cache regressions."""
from __future__ import annotations

from collections import Counter
import contextlib
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.analyzers import taint_js as taint
from ubs_core.registry import RunContext
from ubs_core.js_modules import ModuleGraph
from ubs_core import js_scan


class ModuleTaintTests(unittest.TestCase):
    def run(self, result=None):
        started = time.monotonic()
        print(f'[{self.id()}] RUN', flush=True)
        result = super().run(result)
        failed = any(case is self for case, _ in (*result.failures, *result.errors))
        print(f'[{self.id()}] {"FAIL" if failed else "PASS"} ({time.monotonic() - started:.3f}s)', flush=True)
        return result

    def write(self, root, sources):
        paths = []
        for name, source in sources.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source + '\n', encoding='utf-8')
            paths.append(path)
        return paths

    def scan(self, sources, *expected, select=None):
        with tempfile.TemporaryDirectory(prefix='ubs-js-modules-') as tmp:
            root = Path(tmp).resolve()
            paths = self.write(root, sources)
            selected = paths if select is None else [root / name for name in select]
            findings = list(taint.run(RunContext(lang='javascript', files=selected)))
            actual = Counter((Path(f['path']).relative_to(root).as_posix(), f['rule'].rsplit('.', 1)[-1]) for f in findings)
            self.assertEqual(actual, Counter(expected), (sources, findings))
            for finding in findings:
                self.assertGreater(finding['line'], 0)
                self.assertGreater(finding['col'], 0)
                self.assertIn(' -> ', finding['message'])
            return findings

    def assert_report_findings(self, report, root, expected):
        """Validate both public report dialects independently, including counts."""
        self.assertEqual(report['status'], 'ok', report)
        if 'findings' not in report:
            # The meta-runner omits this array when every scanner is empty.
            # Omission must not conceal an expected record or a nonempty raw
            # channel: check the independent channels and aggregate counts.
            self.assertIsNone(expected, report)
            self.assertTrue(all(not scanner['findings'] for scanner in report['scanners']), report)
            self.assertEqual([report['totals'][level] for level in ('critical','warning','info')], [0,0,0], report)
        channels = [(report.get('findings', []), 'rule_id', 'file')]
        channels.extend((scanner['findings'], 'rule', 'path')
                        for scanner in report['scanners'] if scanner['language'] == 'js')
        self.assertGreaterEqual(len(channels), 2, report)
        for records, rule_key, path_key in channels:
            found = []
            for record in records:
                rule = record[rule_key]
                if not rule.startswith(('js.taint.', 'javascript.taint.')):
                    continue
                location = Path(record[path_key])
                # A single-file shadow workspace reports paths relative to
                # the original scan root, not the test runner's directory.
                if not location.is_absolute():
                    location = root / location
                path = location.resolve().relative_to(root.resolve()).as_posix()
                found.append((path, rule.rsplit('.', 1)[-1]))
                self.assertGreater(record['line'], 0, record)
                self.assertGreater(record['col'], 0, record)
                self.assertEqual(record['severity'], 'critical', record)
                self.assertFalse(record['suppressed'], record)
            self.assertEqual(Counter(found), Counter([expected] if expected else []), report)

    @staticmethod
    def shell_function(name, path=None):
        """Exercise the actual selector without executing the scanner startup."""
        lines = (path or ROOT / 'ubs').read_text(encoding='utf-8').splitlines(keepends=True)
        start = next(i for i, line in enumerate(lines) if line.startswith(name + '(){'))
        end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith('}'))
        return ''.join(lines[start:end + 1])

    def test_module_format_suffixes_are_explicit_source_targets(self):
        script = self.shell_function('looks_like_source_path') + self.shell_function('lang_for_source_file')
        script += '\nlooks_like_source_path "$1" && lang_for_source_file "$1"\n'
        for suffix in ('mts', 'cts', 'ts', 'tsx', 'mjs', 'cjs'):
            with self.subTest(suffix=suffix):
                result = subprocess.run(['bash', '-c', script, 'selector', f'src/file.{suffix}'],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual((result.returncode, result.stdout.strip()), (0, 'js'), result.stderr)

    def test_module_format_suffixes_are_detected_with_and_without_ripgrep(self):
        for suffix in ('mts', 'cts'):
            for use_rg in (False, True):
                if use_rg and not shutil.which('rg'):
                    continue  # The find path is still exercised on minimal hosts.
                with self.subTest(suffix=suffix, ripgrep=use_rg), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    self.write(root, {f'app.{suffix}': 'const value: string = "hello";'})
                    probe = 'command -v "$1" >/dev/null' if use_rg else 'return 1'
                    script = 'need_cmd(){ ' + probe + '; }\n' + self.shell_function('detect_lang')
                    script += '\nPROJECT_DIR="$1"; TMPDIR_RUN=""; detect_lang js\n'
                    result = subprocess.run(['bash', '-c', script, 'selector', str(root)],
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_contract_and_module_defaults_cover_module_format_suffixes(self):
        contract = json.loads((ROOT / 'modules/contract.json').read_text())
        # These are independent selection layers: a supported analyzer suffix
        # must survive both the meta-runner contract and the module file list.
        languages = contract['modules']
        expected = {'mts', 'cts'}
        self.assertTrue(expected <= set(languages['js']['extensions']))
        for path, prefix in ((ROOT / 'ubs', 'SOURCE_EXTENSIONS="'),
                             (ROOT / 'modules/ubs-js.sh', 'INCLUDE_EXT="')):
            line = next(line for line in path.read_text().splitlines() if line.startswith(prefix))
            self.assertTrue(expected <= set(line.split('"')[1].split(',')), path)

    def test_module_format_suffixes_require_the_ast_engine(self):
        # Substitute only the external-tool availability probe. A fallthrough
        # into a scanner is an explicit failure, not a fake clean scan.
        function = self.shell_function('run_contract_v2_js', ROOT / 'modules/ubs-js.sh')
        for suffix in ('mts', 'cts', 'ts', 'tsx', 'jsx'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory(prefix='ubs-ts-ast-gate-') as tmp:
                target = self.write(Path(tmp), {f'app.{suffix}': 'eval(req.query.code);'})[0]
                script = function + '''
check_ast_grep(){ return 1; }
ubs_resolve_helpers_dir(){ printf -v "$1" '%s' "$TMPDIR"; }
python3(){ echo 'UNEXPECTED_SCANNER_EXECUTION'; return 99; }
run_v2_legacy_parity_bridges(){ return 0; }
PROJECT_DIR="$1"; FORMAT=json; USER_RULES_REQUESTED=0
run_contract_v2_js
'''
                result = subprocess.run(['bash', '-c', script, 'ast-gate', str(target)],
                                        env={**os.environ, 'TMPDIR': tmp},
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
                self.assertIn('ast-grep is required', result.stdout)
                self.assertNotIn('UNEXPECTED_SCANNER_EXECUTION', result.stdout)

    @unittest.skipUnless(shutil.which('node'), 'requires Node for the existing narrowing helper')
    def test_module_format_suffixes_retain_type_narrowing_checks(self):
        for suffix in ('mts', 'cts'):
            for mode in ('single', 'directory'):
                with self.subTest(suffix=suffix, mode=mode), tempfile.TemporaryDirectory(prefix='ubs-ts-narrow-') as tmp:
                    root = Path(tmp)
                    target = self.write(root, {f'app.{suffix}':
                        'function render(value: string | null) {\n'
                        '  if (!value) { console.log("missing"); }\n'
                        '  console.log(value.length);\n}'})[0]
                    result = subprocess.run(['node', str(ROOT / 'modules/helpers/type_narrowing_ts.js'),
                                             str(target if mode == 'single' else root)],
                                            capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(str(target) + ':', result.stdout)

    def test_report_dialects_retain_exact_paths_counts_and_locations(self):
        with tempfile.TemporaryDirectory(prefix='ubs-module-report-') as tmp:
            root = Path(tmp).resolve()
            location = str(root / 'src/app.mjs')
            common = {'line': 2, 'col': 3, 'severity': 'critical', 'suppressed': False}
            merged = {**common, 'rule_id': 'javascript.taint.xss', 'file': location}
            scanner = {**common, 'rule': 'javascript.taint.xss', 'path': location}
            report = {'status': 'ok', 'findings': [merged],
                      'scanners': [{'language': 'js', 'findings': [scanner]}]}
            expected = ('src/app.mjs', 'xss')
            self.assert_report_findings(report, root, expected)
            report['findings'] = [merged, merged]
            with self.assertRaises(AssertionError):
                self.assert_report_findings(report, root, expected)
            report['findings'] = [{**merged, 'file': str(root / 'wrong.mjs')}]
            with self.assertRaises(AssertionError):
                self.assert_report_findings(report, root, expected)
            report['findings'] = [merged]
            report['scanners'][0]['findings'] = [{**scanner, 'line': 0}]
            with self.assertRaises(AssertionError):
                self.assert_report_findings(report, root, expected)

    def test_relative_report_paths_are_rooted_in_the_scan_not_test_directory(self):
        with tempfile.TemporaryDirectory(prefix='ubs-relative-report-') as tmp:
            root = Path(tmp).resolve()
            common = {'line': 1, 'col': 4, 'severity': 'critical', 'suppressed': False}
            raw = {**common, 'rule':'javascript.taint.eval', 'path':'src/app.mts'}
            merged = {**common, 'rule_id':'javascript.taint.eval', 'file':'src/app.mts'}
            report = {'status':'ok','findings':[merged],
                      'scanners':[{'language':'js','findings':[raw]}]}
            self.assert_report_findings(report, root, ('src/app.mts','eval'))
            for bad in ('other/app.mts', '../app.mts'):
                report['findings'] = [{**merged,'file':bad}]
                with self.assertRaises((AssertionError, ValueError)):
                    self.assert_report_findings(report, root, ('src/app.mts','eval'))
    def test_typescript_runtime_extension_finds_selected_source(self):
        for importer, specifier, target in (
            ('app.ts', './lib.js', 'lib.ts'),
            ('app.tsx', './lib.js', 'lib.tsx'),
            ('app.mts', './lib.mjs', 'lib.mts'),
            ('app.cts', './lib.cjs', 'lib.cts'),
            ('app.ts', './lib.jsx', 'lib.tsx'),
        ):
            with self.subTest(importer=importer, target=target):
                self.scan({target: 'export function read() { return req.query.html; }',
                           importer: f'import {{read}} from "{specifier}"; res.send(read());'},
                          (importer, 'xss'))

    def test_typescript_extension_resolves_helper_sink(self):
        self.scan({'service/send.ts': 'export function send(x) { res.send(x); }',
                   'route.ts': 'import {send} from "./service/send.js"; send(req.query.html);'},
                  ('service/send.ts', 'xss'))

    def test_typescript_extension_preserves_clean_return(self):
        self.scan({'lib.ts': 'export function clean(x) { return "safe"; }',
                   'app.ts': 'import {clean} from "./lib.js"; res.send(clean(req.query.html));'})

    def test_typescript_extension_keeps_sanitizer_domains(self):
        self.scan({'lib.ts': 'export function clean(x) { return DOMPurify.sanitize(x); }',
                   'app.ts': 'import {clean} from "./lib.js"; res.send(clean(req.query.html)); eval(clean(req.query.html));'},
                  ('app.ts', 'eval'))

    def test_typescript_extension_preserves_borrowed_mutations(self):
        self.scan({'lib.ts': 'export function set(b,x) { b.html=x; }',
                   'app.ts': 'import {set} from "./lib.js"; const b={}; set(b,req.query.html); res.send(b.html);'},
                  ('app.ts', 'xss'))
        self.scan({'lib.ts': 'export function clear(b) { b.html="safe"; }',
                   'app.ts': 'import {clear} from "./lib.js"; const b={html:req.query.html}; clear(b); res.send(b.html);'})

    def test_typescript_extension_reexport_chain(self):
        self.scan({'source.ts': 'export function read() { return req.query.html; }',
                   'barrel.ts': 'export {read} from "./source.js";',
                   'app.ts': 'import {read} from "./barrel.js"; res.send(read());'}, ('app.ts','xss'))

    def test_typescript_extension_namespace_reexport(self):
        self.scan({'source.mts': 'export function read() { return req.query.html; }',
                   'barrel.mts': 'export * as api from "./source.mjs";',
                   'app.mts': 'import * as root from "./barrel.mjs"; res.send(root.api.read());'},
                  ('app.mts','xss'))

    def test_typescript_extension_prefers_source_over_emitted_sibling(self):
        self.scan({'lib.ts': 'export function read() { return req.query.html; }',
                   'lib.js': 'export function read() { return "safe"; }',
                   'app.ts': 'import {read} from "./lib.js"; res.send(read());'}, ('app.ts','xss'))

    def test_javascript_import_keeps_explicit_runtime_sibling(self):
        self.scan({'lib.ts': 'export function read() { return req.query.html; }',
                   'lib.js': 'export function read() { return "safe"; }',
                   'app.js': 'import {read} from "./lib.js"; res.send(read());'})

    def test_typescript_extension_uses_runtime_when_source_is_not_selected(self):
        self.scan({'lib.ts': 'export function read() { return "safe"; }',
                   'lib.js': 'export function read() { return req.query.html; }',
                   'app.ts': 'import {read} from "./lib.js"; res.send(read());'}, ('app.ts','xss'),
                  select=['app.ts','lib.js'])

    def test_typescript_extension_never_loads_excluded_source(self):
        self.scan({'lib.ts': 'export function read() { return req.query.html; }',
                   'app.ts': 'import {read} from "./lib.js"; res.send(read());'}, select=['app.ts'])

    def test_typescript_extension_unresolved_sanitizer_keeps_taint(self):
        self.scan({'lib.ts': 'export function escapeHtml(x) { return "safe"; }',
                   'app.ts': 'import {escapeHtml} from "./lib.js"; res.send(escapeHtml(req.query.html));'},
                  ('app.ts','xss'), select=['app.ts'])

    def test_declaration_only_files_cannot_prove_clean_calls(self):
        for declaration, specifier in (('lib.d.ts','./lib.d.ts'), ('lib.d.mts','./lib.d.mts'), ('lib.d.cts','./lib.d.cts')):
            with self.subTest(declaration=declaration):
                self.scan({declaration: 'export declare function clean(x: string): string;',
                           'app.ts': f'import {{clean}} from "{specifier}"; res.send(clean(req.query.html));'},
                          ('app.ts','xss'))
                with tempfile.TemporaryDirectory(prefix='ubs-types-only-') as tmp:
                    paths=self.write(Path(tmp), {declaration: 'export declare function read(): string;',
                                                'app.ts': f'import {{read}} from "{specifier}"; res.send(read());'})
                    graph=ModuleGraph(paths)
                    self.assertNotIn(paths[0].resolve(), graph.modules)
                    self.assertEqual(graph.edges[paths[1].resolve()], set())

    def test_declarations_do_not_hide_the_selected_runtime_implementation(self):
        self.scan({'lib.d.ts': 'export declare function read(): string;',
                   'lib.js': 'export function read() { return req.query.html; }',
                   'app.ts': 'import {read} from "./lib.js"; res.send(read());'}, ('app.ts','xss'))

    def test_explicit_typescript_extension_can_resolve_an_implementation_sibling(self):
        self.scan({'lib.tsx': 'export function read() { return req.query.html; }',
                   'app.ts': 'import {read} from "./lib.ts"; res.send(read());'}, ('app.ts','xss'))

    def test_extension_substitution_does_not_cross_module_format_suffixes(self):
        self.scan({'lib.cts': 'export function read() { return req.query.html; }',
                   'app.mts': 'import {read} from "./lib.mjs"; res.send(read());'})
        self.scan({'lib.mts': 'export function read() { return req.query.html; }',
                   'app.cts': 'import {read} from "./lib.cjs"; res.send(read());'})

    def test_typescript_extension_exact_index_and_parent_paths(self):
        self.scan({'lib/index.ts': 'export function read() { return req.query.html; }',
                   'routes/app.ts': 'import {read} from "../lib/index.js"; res.send(read());'},
                  ('routes/app.ts','xss'))

    def test_typescript_extension_component_keeps_parallel_input_together(self):
        with tempfile.TemporaryDirectory(prefix='ubs-module-ts-component-') as tmp:
            paths=self.write(Path(tmp).resolve(), {'lib.ts':'export function read(){return req.query.html;}',
                    'app.ts':'import {read} from "./lib.js"; res.send(read());', 'other.ts':'export const answer=42;'})
            graph=ModuleGraph(paths)
            self.assertEqual({frozenset(m.path.name for m in component) for component in graph.components()},
                             {frozenset(('lib.ts','app.ts')), frozenset(('other.ts',))})

    def test_typescript_extension_cache_invalidation(self):
        with tempfile.TemporaryDirectory(prefix='ubs-module-ts-cache-') as tmp:
            root=Path(tmp).resolve()
            paths=self.write(root, {'lib.ts':'export function read(){return "safe";}',
                'app.ts':'import {read} from "./lib.js"; res.send(read());'})
            listing, sink=root/'files', root/'sink'
            listing.write_bytes(b'\0'.join(os.fsencode(p) for p in paths)+b'\0')
            def scan():
                js_scan.main(['--files-from',str(listing),'--sink',str(sink),'--project-dir',str(root)])
                return [r for line in sink.read_text().splitlines()
                        if (r:=json.loads(line))['rule'].startswith('javascript.taint.')]
            with mock.patch.dict(os.environ, {'UBS_CACHE_DIR':str(root/'cache'), 'UBS_NO_CACHE':'0'}):
                self.assertEqual(scan(), [])
                self.assertEqual(scan(), [])
                paths[0].write_text('export function read(){return req.query.html;}')
                self.assertEqual([r['path'] for r in scan()], [str(paths[1])])
                paths[0].write_text('export function read(){return "safe";}')
                self.assertEqual(scan(), [])

    def test_typescript_extension_substitutes_before_resolving_runtime_symlink(self):
        with tempfile.TemporaryDirectory(prefix='ubs-ts-link-') as tmp:
            root=Path(tmp).resolve()
            paths=self.write(root, {'lib.ts':'export function read(){return req.query.html;}',
                'emitted.js':'export function read(){return "safe";}',
                'app.ts':'import {read} from "./lib.js"; res.send(read());'})
            (root/'lib.js').symlink_to(root/'emitted.js')
            graph=ModuleGraph([*paths, root/'lib.js'])
            self.assertEqual(graph.resolve(graph.modules[paths[2]], './lib.js').path, paths[0])
            findings=list(taint.run(RunContext(lang='javascript',files=[*paths,root/'lib.js'])))
            self.assertEqual([(r['path'],r['rule']) for r in findings],
                             [(str(paths[2]),'javascript.taint.xss')])

    @unittest.skipUnless(shutil.which('node') and shutil.which('tsc'), 'requires TypeScript compiler and Node.js')
    def test_extension_substitution_agrees_with_typescript_resolver(self):
        # The independent compiler host can see exactly the selected files.
        # No package configuration or unselected file participates in either
        # resolver. Declaration-only files intentionally have a different
        # taint policy and are covered by explicit clean/unsafe tests instead.
        compiler=Path(shutil.which('tsc')).resolve().parents[1]
        # TypeScript 7 is the native compiler and ships no JavaScript API
        # (its package entry is lib/version.cjs). Runner images now carry it
        # as the global tsc; javascript-modules.yml pins 5.8.3 and refuses
        # skips, so the oracle still runs in CI.
        probe=subprocess.run(['node','-e',
            'process.exit(typeof require(process.argv[1]).resolveModuleName==="function"?0:3)',
            str(compiler)],capture_output=True,text=True,timeout=10)
        if probe.returncode:
            errors=[line.strip() for line in probe.stderr.splitlines() if 'Error' in line]
            reason=errors[0] if errors else 'resolveModuleName is not a function'
            self.skipTest(f'{compiler} has no JavaScript compiler API (TypeScript 7+?): {reason}')
        cases=[
            ('./lib.js', ['lib.ts']), ('./lib.js', ['lib.tsx']),
            ('./lib.js', ['lib.ts','lib.tsx','lib.js']),
            ('./lib.js', ['lib.js']), ('./lib.js', ['lib.jsx']),
            ('./lib.jsx', ['lib.ts','lib.tsx']), ('./lib.jsx', ['lib.ts']),
            ('./lib.mjs', ['lib.mts','lib.mjs']), ('./lib.mjs', ['lib.mjs']),
            ('./lib.cjs', ['lib.cts','lib.cjs']), ('./lib.cjs', ['lib.cjs']),
            ('./lib.ts', ['lib.tsx']), ('./lib.mjs', ['lib.cts']),
            ('./lib.cjs', ['lib.mts']), ('../pkg/index.js', ['pkg/index.ts']),
            ('./lib.ts', ['lib.ts','lib.tsx','lib.js']), ('./lib.ts', ['lib.js']),
            ('./lib.tsx', ['lib.tsx','lib.ts']), ('./lib.tsx', ['lib.jsx']),
            ('./lib.mts', ['lib.mjs']), ('./lib.cts', ['lib.cjs']),
        ]
        program=r"""
const ts = require(process.argv[1]);
const path = require('node:path');
const input = JSON.parse(process.argv[2]);
const selected = new Set(input.files.map(p => path.resolve(p)));
const host = {
  fileExists: p => selected.has(path.resolve(p)),
  readFile: p => selected.has(path.resolve(p)) ? ts.sys.readFile(p) : undefined,
  directoryExists: p => [...selected].some(f => f.startsWith(path.resolve(p) + path.sep)),
  realpath: ts.sys.realpath,
  getCurrentDirectory: () => path.dirname(input.importer),
};
const result = ts.resolveModuleName(input.specifier, input.importer,
  {module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext}, host);
console.log(JSON.stringify(result.resolvedModule?.resolvedFileName ?? null));
"""
        for specifier,names in cases:
            with self.subTest(specifier=specifier,names=names), tempfile.TemporaryDirectory(prefix='ubs-ts-oracle-') as tmp:
                root=Path(tmp).resolve()
                if specifier.startswith('../'):
                    importer='app/index.ts'
                else:
                    importer='app.ts'
                paths=self.write(root,{importer:f'import {{read}} from "{specifier}";',
                                      **{name:'export function read(){return "safe";}' for name in names}})
                graph=ModuleGraph(paths)
                resolved=graph.resolve(graph.modules[paths[0]],specifier)
                result=subprocess.run(['node','-e',program,str(compiler),json.dumps({
                    'files':list(map(str,paths)), 'importer':str(paths[0]), 'specifier':specifier})],
                    capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)
                expected=json.loads(result.stdout)
                self.assertEqual(str(resolved.path) if resolved else None, expected)

    @unittest.skipUnless(shutil.which('ast-grep'), 'requires ast-grep for the actual meta-runner')
    def test_meta_runner_typescript_runtime_extensions(self):
        cases=[
            ('typed-source','lib.ts','app.ts','./lib.js',
             'export function read(){return req.query.html;}','res.send(read());',('app.ts','xss')),
            ('typed-sink','lib.ts','app.ts','./lib.js',
             'export function read(x){res.send(x);}','read(req.query.html);',('lib.ts','xss')),
            ('typed-clean','lib.ts','app.ts','./lib.js',
             'export function read(x){return "safe";}','res.send(read(req.query.html));',None),
            ('typed-heap','lib.ts','app.ts','./lib.js',
             'export function read(b,x){b.html=x;}','const b={};read(b,req.query.html);res.send(b.html);',('app.ts','xss')),
            ('typed-mts','lib.mts','app.mts','./lib.mjs',
             'export function read(){return req.query.html;}','res.send(read());',('app.mts','xss')),
            ('typed-cts','lib.cts','app.cts','./lib.cjs',
             'export function read(){return req.query.html;}','res.send(read());',('app.cts','xss')),
        ]
        for name,library_name,caller_name,specifier,library,body,expected in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix='ubs-ts-modules-e2e-') as tmp:
                root=Path(tmp).resolve()
                paths=self.write(root,{library_name:library,caller_name:f'import {{read}} from "{specifier}"; '+body})
                result=subprocess.run([str(ROOT/'ubs'),*(str(p) for p in paths),'--only=js','--format=json','--ci'],
                    cwd=tmp,capture_output=True,text=True,timeout=120,
                    env={**os.environ,'UBS_NO_AUTO_UPDATE':'1','UBS_NO_CACHE':'1'})
                artifact=ROOT/'test-suite/artifacts/javascript-modules'/name
                artifact.mkdir(parents=True,exist_ok=True)
                (artifact/'stdout.log').write_text(result.stdout)
                (artifact/'stderr.log').write_text(result.stderr)
                self.assertIn(result.returncode,(0,1),(result.stdout,result.stderr))
                report=json.loads(result.stdout)
                (artifact/'result.json').write_text(json.dumps(report,indent=2))
                self.assert_report_findings(report,root,expected)

    @unittest.skipUnless(shutil.which('ast-grep'), 'requires ast-grep for the actual meta-runner')
    def test_module_format_suffixes_scan_directories_and_single_files(self):
        for suffix in ('mts', 'cts'):
            for mode in ('single', 'directory'):
                with self.subTest(suffix=suffix, mode=mode), tempfile.TemporaryDirectory(prefix='ubs-ts-scope-') as tmp:
                    root = Path(tmp).resolve()
                    target = self.write(root, {f'src/app.{suffix}': 'eval(req.query.code);'})[0]
                    result = subprocess.run([str(ROOT / 'ubs'), str(target if mode == 'single' else root),
                                             '--only=js', '--format=json', '--ci'], cwd=tmp,
                                            capture_output=True, text=True, timeout=120,
                                            env={**os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'UBS_NO_CACHE': '1'})
                    self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
                    report = json.loads(result.stdout)
                    self.assertEqual(report['totals']['files'], 1, report)
                    self.assert_report_findings(report, root, (f'src/app.{suffix}', 'eval'))

    @unittest.skipUnless(shutil.which('ast-grep'), 'requires ast-grep for the actual meta-runner')
    def test_module_format_suffixes_scan_index_bytes_not_worktree(self):
        for suffix in ('mts', 'cts'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory(prefix='ubs-ts-index-') as tmp:
                root = Path(tmp).resolve()
                subprocess.run(['git', 'init', '-q', '-b', 'main', str(root)], check=True, timeout=10)
                target = self.write(root, {f'app.{suffix}': 'eval(req.query.code);'})[0]
                subprocess.run(['git', '-C', str(root), 'add', target.name], check=True, timeout=10)
                target.write_text('const value = "clean unstaged replacement";\n')
                result = subprocess.run([str(ROOT / 'ubs'), '--staged', '--only=js', '--format=json', '--ci'],
                                        cwd=tmp, capture_output=True, text=True, timeout=120,
                                        env={**os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'UBS_NO_CACHE': '1'})
                self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
                report = json.loads(result.stdout)
                self.assertEqual(report['totals']['files'], 1, report)
                self.assert_report_findings(report, root, (target.name, 'eval'))

    def test_empty_meta_report_can_omit_merged_array_but_not_hide_findings(self):
        with tempfile.TemporaryDirectory(prefix='ubs-empty-module-report-') as tmp:
            root=Path(tmp).resolve()
            report={'status':'ok', 'totals':{'critical':0,'warning':0,'info':0},
                    'scanners':[{'language':'js','findings':[]}]}
            self.assert_report_findings(report,root,None)
            with self.assertRaises(AssertionError):
                self.assert_report_findings(report,root,('app.mjs','xss'))
            report['totals']['critical']=1
            with self.assertRaises(AssertionError):
                self.assert_report_findings(report,root,None)
            report['totals']['critical']=0
            report['scanners'][0]['findings']=[{'rule':'javascript.taint.xss','path':str(root/'app.mjs'),
                'line':1,'col':1,'severity':'critical','suppressed':False}]
            with self.assertRaises(AssertionError):
                self.assert_report_findings(report,root,None)

    def test_deep_named_reexport_chain_does_not_use_python_recursion(self):
        with tempfile.TemporaryDirectory(prefix='ubs-deep-export-') as tmp:
            root=Path(tmp).resolve()
            sources={f'm{i}.mjs':f'export {{read}} from "./m{i+1}.mjs";' for i in range(1500)}
            sources['m1500.mjs']='export function read(){return req.query.html;}'
            sources['app.mjs']='import {read} from "./m0.mjs"; res.send(read());'
            paths=self.write(root,sources)
            graph=ModuleGraph(paths)
            expected=(graph.modules[root/'m1500.mjs'],'read')
            self.assertEqual(graph.exported(graph.modules[root/'m0.mjs'],'read'),expected)
            for i in (1,500,1499,1500):
                self.assertEqual(graph.exported(graph.modules[root/f'm{i}.mjs'],'read'),expected)
            findings=list(taint.run(RunContext(lang='javascript',files=paths)))
            self.assertEqual([(r['path'],r['rule']) for r in findings],
                             [(str(root/'app.mjs'),'javascript.taint.xss')])

    def test_deep_star_reexport_chain_does_not_use_python_recursion(self):
        with tempfile.TemporaryDirectory(prefix='ubs-deep-star-') as tmp:
            root=Path(tmp).resolve()
            sources={f'm{i}.mjs':f'export * from "./m{i+1}.mjs";' for i in range(1500)}
            sources['m1500.mjs']='export function read(){return "safe";}'
            paths=self.write(root,sources);graph=ModuleGraph(paths)
            self.assertEqual(graph.exported(graph.modules[root/'m0.mjs'],'read'),
                             (graph.modules[root/'m1500.mjs'],'read'))
            self.assertIsNone(graph.exported(graph.modules[root/'m0.mjs'],'missing'))

    def test_deep_source_free_export_cycle_terminates_without_a_binding(self):
        with tempfile.TemporaryDirectory(prefix='ubs-deep-cycle-') as tmp:
            root=Path(tmp).resolve()
            paths=self.write(root,{f'm{i}.mjs':f'export * from "./m{(i+1)%1500}.mjs";' for i in range(1500)})
            graph=ModuleGraph(paths)
            self.assertIsNone(graph.exported(graph.modules[root/'m0.mjs'],'read'))

    def test_ambiguous_star_branch_cannot_be_hidden_by_a_unique_sibling(self):
        with tempfile.TemporaryDirectory(prefix='ubs-star-conflict-') as tmp:
            root=Path(tmp).resolve()
            paths=self.write(root, {'a.mjs':'export function f(x){return "safe";}',
                'b.mjs':'export function f(x){return x;}',
                'conflict.mjs':'export * from "./a.mjs"; export * from "./b.mjs";',
                'entry.mjs':'export * from "./conflict.mjs"; export * from "./a.mjs";'})
            graph=ModuleGraph(paths)
            self.assertIsNone(graph.exported(graph.modules[root/'conflict.mjs'],'f'))
            self.assertIsNone(graph.exported(graph.modules[root/'entry.mjs'],'f'))

    def test_diamond_star_exports_of_same_binding_are_not_ambiguous(self):
        self.scan({'leaf.mjs':'export function read(){return req.query.html;}',
            'left.mjs':'export * from "./leaf.mjs";',
            'right.mjs':'export {read} from "./leaf.mjs";',
            'barrel.mjs':'export * from "./left.mjs"; export * from "./right.mjs";',
            'app.mjs':'import {read} from "./barrel.mjs"; res.send(read());'},('app.mjs','xss'))

    def test_cyclic_star_exports_reach_the_unique_leaf(self):
        self.scan({'leaf.mjs':'export function read(){return req.query.html;}',
            'a.mjs':'export * from "./b.mjs";',
            'b.mjs':'export * from "./a.mjs"; export * from "./leaf.mjs";',
            'app.mjs':'import {read} from "./a.mjs"; res.send(read());'},('app.mjs','xss'))

    def test_explicit_export_wins_over_conflicting_stars(self):
        self.scan({'a.mjs':'export function read(){return req.query.html;}',
            'b.mjs':'export function read(){return "safe";}',
            'barrel.mjs':'export * from "./a.mjs"; export * from "./b.mjs"; export {read} from "./a.mjs";',
            'app.mjs':'import {read} from "./barrel.mjs"; res.send(read());'},('app.mjs','xss'))

    def test_reexport_resolution_respects_explicit_cycle_boundary(self):
        with tempfile.TemporaryDirectory(prefix='ubs-export-boundary-') as tmp:
            root=Path(tmp).resolve()
            paths=self.write(root, {'a.mjs':'export {read} from "./b.mjs";',
                                   'b.mjs':'export function read(){return "safe";}'})
            graph=ModuleGraph(paths);a,b=(graph.modules[p] for p in paths)
            self.assertEqual(graph.exported(a,'read'),(b,'read'))
            self.assertIsNone(graph.exported(a,'read',frozenset(((b.path,'read'),))))
            self.assertEqual(graph.exported(a,'read'),(b,'read'))

    def test_exported_source_return(self):
        self.scan({'lib.js': 'export function read() { return req.query.html; }',
                   'app.js': 'import {read} from "./lib.js"; res.send(read());'}, ('app.js', 'xss'))

    def test_exported_sink_effect(self):
        findings = self.scan({'lib.js': 'export function send(value) {\n  res.send(value);\n}',
                             'app.js': 'import {send} from "./lib.js"; send(req.query.html);'}, ('lib.js', 'xss'))
        self.assertEqual((findings[0]['line'], findings[0]['col']), (2, 3))

    def test_constant_return_does_not_pass_unused_input(self):
        self.scan({'lib.js': 'export function clean(x) { return "safe"; }',
                   'app.js': 'import {clean} from "./lib.js"; res.send(clean(req.query.html));'})

    def test_named_and_local_export_aliases(self):
        self.scan({'lib.js': 'function read() { return req.query.html; } export {read as get};',
                   'app.js': 'import {get as read} from "./lib.js"; res.send(read());'}, ('app.js', 'xss'))

    def test_exported_arrow(self):
        self.scan({'lib.ts': 'export const read = (): string => req.query.html;',
                   'app.ts': 'import {read} from "./lib"; res.send(read());'}, ('app.ts', 'xss'))

    def test_default_named_and_anonymous_functions(self):
        for body in ('export default function read() { return req.query.html; }',
                     'export default function () { return req.query.html; }',
                     'export default () => req.query.html;'):
            with self.subTest(body=body):
                self.scan({'lib.js': body, 'app.js': 'import read from "./lib.js"; res.send(read());'}, ('app.js', 'xss'))

    def test_namespace_call(self):
        self.scan({'lib.mjs': 'export function read() { return req.query.html; }',
                   'app.mjs': 'import * as lib from "./lib.mjs"; res.send(lib.read());'}, ('app.mjs', 'xss'))

    def test_mixed_default_and_named_import(self):
        self.scan({'lib.js': 'export default function clean(x) { return "safe"; } export function read() { return req.query.html; }',
                   'app.js': 'import clean, {read as get} from "./lib.js"; res.send(clean(req.query.html)); eval(get());'}, ('app.js', 'eval'))

    def test_selected_import_does_not_trust_sanitizer_name(self):
        self.scan({'lib.js': 'export function escapeHtml(x) { return x; }',
                   'app.js': 'import {escapeHtml} from "./lib.js"; res.send(escapeHtml(req.query.html));'}, ('app.js', 'xss'))

    def test_sanitizer_wrapper_retains_domain(self):
        self.scan({'lib.js': 'export function escape(x) { return DOMPurify.sanitize(x); }',
                   'app.js': 'import {escape} from "./lib.js"; res.send(escape(req.query.html)); eval(escape(req.query.code));'}, ('app.js', 'eval'))

    def test_reexport_chain(self):
        self.scan({'lib.js': 'export function read() { return req.query.html; }',
                   'barrel.js': 'export {read as get} from "./lib.js";',
                   'app.js': 'import {get} from "./barrel.js"; res.send(get());'}, ('app.js', 'xss'))

    def test_import_then_export(self):
        self.scan({'lib.js': 'export function read() { return req.query.html; }',
                   'barrel.js': 'import {read} from "./lib.js"; export {read};',
                   'app.js': 'import {read} from "./barrel.js"; res.send(read());'}, ('app.js', 'xss'))

    def test_star_reexports_and_cycles_terminate(self):
        self.scan({'lib.js': 'export * from "./barrel.js"; export function read() { return req.query.html; }',
                   'barrel.js': 'export * from "./lib.js";',
                   'app.js': 'import {read} from "./barrel.js"; res.send(read());'}, ('app.js', 'xss'))

    def test_ambiguous_star_export_does_not_apply_clean_summary(self):
        self.scan({'a.js': 'export function f(x) { return "safe"; }',
                   'b.js': 'export function f(x) { return x; }',
                   'barrel.js': 'export * from "./a.js"; export * from "./b.js";',
                   'app.js': 'import {f} from "./barrel.js"; res.send(f(req.query.html));'}, ('app.js', 'xss'))

    def test_mutually_recursive_modules(self):
        self.scan({'a.js': 'import {b} from "./b.js"; export function a(x) { if(flag) return x; return b(x); }',
                   'b.js': 'import {a} from "./a.js"; export function b(x) { return a(x); }',
                   'app.js': 'import {b} from "./b.js"; eval(b(req.query.code));'}, ('app.js', 'eval'))

    def test_captured_module_value(self):
        self.scan({'lib.js': 'const value = req.query.html; export function read() { return value; }',
                   'app.js': 'import {read} from "./lib.js"; res.send(read());'}, ('app.js', 'xss'))

    def test_exported_scalar_and_namespace_value(self):
        self.scan({'lib.js': 'export const value = req.query.html;',
                   'app.js': 'import {value} from "./lib.js"; import * as lib from "./lib.js"; res.send(value); eval(lib.value);'},
                  ('app.js', 'xss'), ('app.js', 'eval'))

    def test_exported_object_preserves_fields(self):
        self.scan({'lib.js': 'export const box = {html: req.query.html, clean: "safe"};',
                   'app.js': 'import {box} from "./lib.js"; res.send(box.clean); eval(box.html);'}, ('app.js', 'eval'))

    def test_borrowed_mutation_across_module(self):
        self.scan({'lib.js': 'export function set(box, value) { box.html = value; }',
                   'app.js': 'import {set} from "./lib.js"; const box = {}; set(box, req.query.html); res.send(box.html);'}, ('app.js', 'xss'))

    def test_clean_overwrite_across_module(self):
        self.scan({'lib.js': 'export function clear(box) { box.html = "safe"; }',
                   'app.js': 'import {clear} from "./lib.js"; const box = {html: req.query.html}; clear(box); res.send(box.html);'})

    def test_separate_factory_call_identities(self):
        self.scan({'lib.js': 'export function make(x) { return {html: x}; }',
                   'app.js': 'import {make} from "./lib.js"; const raw=make(req.query.html); const safe=make("safe"); res.send(safe.html); eval(raw.html);'}, ('app.js', 'eval'))

    def test_imported_parameter_is_shadowed(self):
        self.scan({'lib.js': 'export function read() { return req.query.html; }',
                   'app.js': 'import {read} from "./lib.js"; function f(read) { res.send(read()); }'})

    def test_namespace_parameter_is_shadowed(self):
        self.scan({'lib.js': 'export function read() { return req.query.html; }',
                   'app.js': 'import * as lib from "./lib.js"; function f(lib) { res.send(lib.read()); }'})

    def test_exporter_reassignment_invalidates_clean_summary(self):
        self.scan({'lib.js': 'export let f = x => "safe"; f = external;',
                   'app.js': 'import {f} from "./lib.js"; res.send(f(req.query.html));'}, ('app.js', 'xss'))

    def test_module_globals_are_isolated(self):
        self.scan({'lib.js': 'const html = req.query.html; export function read() { return html; }',
                   'app.js': 'import {read} from "./lib.js"; const html = "safe"; res.send(html); eval(read());'}, ('app.js', 'eval'))

    def test_unselected_dependency_is_not_read(self):
        self.scan({'lib.js': 'export function read() { return req.query.html; }',
                   'app.js': 'import {read} from "./lib.js"; res.send(read());'}, select=['app.js'])

    def test_unresolved_relative_sanitizer_cannot_prove_clean(self):
        for imported, call in (('{escapeHtml}', 'escapeHtml'),
                               ('DOMPurify', 'DOMPurify.sanitize')):
            with self.subTest(imported=imported):
                self.scan({'lib.js': 'export function escapeHtml(x){return x;}',
                           'app.js': f'import {imported} from "./lib.js"; res.send({call}(req.query.html));'},
                          ('app.js', 'xss'), select=['app.js'])
                self.scan({'app.js': f'import {imported} from "./missing"; res.send({call}(req.query.html));'},
                          ('app.js', 'xss'))

    def test_missing_export_does_not_resolve_private_function(self):
        self.scan({'lib.js': 'function f(x) { return "safe"; }',
                   'app.js': 'import {f} from "./lib.js"; res.send(f(req.query.html));'}, ('app.js', 'xss'))

    def test_package_specifiers_are_not_resolved_by_basename(self):
        self.scan({'lib.js': 'export function f(x) { return "safe"; }',
                   'app.js': 'import {f} from "lib"; res.send(f(req.query.html));'}, ('app.js', 'xss'))

    def test_extensionless_index_resolution(self):
        self.scan({'lib/index.js': 'export function read() { return req.query.html; }',
                   'src/app.js': 'import {read} from "../lib"; res.send(read());'}, ('src/app.js', 'xss'))

    def test_comments_and_strings_do_not_create_imports(self):
        self.scan({'lib.js': 'export function f(x) { return "safe"; }',
                   'app.js': '/* import {f} from "./lib.js"; */\nconst example = \'import {f} from "./lib.js";\'; res.send(f(req.query.html));'}, ('app.js', 'xss'))

    def test_type_import_does_not_bind_runtime_helper(self):
        self.scan({'lib.ts': 'export function f(x) { return "safe"; }',
                   'app.ts': 'import type {f} from "./lib"; res.send(f(req.query.html));'}, ('app.ts', 'xss'))

    def test_multiline_import_and_sink_coordinates(self):
        findings = self.scan({'lib.js': 'export function read() { return req.query.html; }',
                              'app.js': 'import {\n read as get,\n} from "./lib.js";\n  res.send(\n get()\n);'}, ('app.js', 'xss'))
        self.assertEqual((findings[0]['line'], findings[0]['col']), (4, 3))

    def test_legacy_and_structured_entrypoints_agree(self):
        with tempfile.TemporaryDirectory(prefix='ubs-module-legacy-') as tmp:
            paths = self.write(Path(tmp).resolve(), {'lib.js': 'export function read() { return req.query.html; }',
                                         'app.js': 'import {read} from "./lib.js"; eval(read());'})
            self.assertEqual(len(list(taint.run(RunContext(lang='javascript', files=paths)))), 1)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(taint.main(['taint_js', tmp]), 0)
            self.assertTrue(output.getvalue().startswith('js.taint.eval\t1\tapp.js:1 '), output.getvalue())

    def test_source_order_does_not_change_results(self):
        with tempfile.TemporaryDirectory(prefix='ubs-module-order-') as tmp:
            paths = self.write(Path(tmp).resolve(), {'z.js': 'export function read() { return req.query.html; }',
                                         'a.js': 'import {read} from "./z.js"; res.send(read());'})
            self.assertEqual(list(taint.run(RunContext(lang='javascript', files=paths))),
                             list(taint.run(RunContext(lang='javascript', files=list(reversed(paths))))))

    def test_prefilter_must_not_remove_source_free_helper(self):
        with tempfile.TemporaryDirectory(prefix='ubs-module-prefilter-') as tmp:
            paths = self.write(Path(tmp).resolve(), {'lib.js': 'export function f(x) { return "safe"; }',
                                         'app.js': 'import {f} from "./lib.js"; res.send(f(req.query.html));'})
            prefilter = mock.Mock()
            prefilter.filter_files_for_analyzer.return_value = [paths[1]]
            sink = io.StringIO()
            js_scan.run_analyzers(paths, sink, prefilter=prefilter)
            records = [json.loads(line) for line in sink.getvalue().splitlines()]
            self.assertFalse([r for r in records if r['rule'] == 'javascript.taint.xss'], records)

    def test_real_scan_cache_invalidates_both_module_endpoints(self):
        with tempfile.TemporaryDirectory(prefix='ubs-module-cache-') as tmp:
            root = Path(tmp).resolve()
            sources = {'lib.js': 'export function f(x) { return "safe"; }',
                       'app.js': 'import {f} from "./lib.js"; res.send(f(req.query.html));',
                       'unrelated.js': 'const answer = 42;'}
            paths = self.write(root, sources)
            listing, sink, stats = root/'files', root/'sink', root/'stats'
            def scan(selected=paths):
                listing.write_bytes(b'\0'.join(os.fsencode(p) for p in selected)+b'\0')
                status = js_scan.main(['--files-from', str(listing), '--sink', str(sink),
                                       '--project-dir', str(root)])
                records = [json.loads(line) for line in sink.read_text().splitlines()]
                self.assertEqual(status, int(any(r['severity'] == 'critical' for r in records)), records)
                return [r for r in records if r['rule'].startswith('javascript.taint.')], json.loads(stats.read_text())
            with mock.patch.dict(os.environ, {'UBS_CACHE_DIR': str(root/'cache'), 'UBS_NO_CACHE':'0',
                                             'UBS_CACHE_FILE':str(stats)}):
                self.assertEqual(scan()[0], [])
                self.assertEqual(scan()[1]['hits'], 3)
                paths[0].write_text('export function f(x) { return x; }')
                findings, cached = scan()
                self.assertEqual([f['rule'] for f in findings], ['javascript.taint.xss'])
                self.assertEqual(cached['hits'], 1)
                self.assertEqual(cached['misses'], 2)
                self.assertEqual(scan()[1]['hits'], 3)
                paths[1].write_text('import {f} from "./lib.js"; res.send(f("safe"));')
                self.assertEqual(scan()[0], [])
                self.assertEqual(scan()[1]['hits'], 3)
                self.assertEqual(scan([paths[1]])[0], [])

    def test_block_shadowing_does_not_resolve_import(self):
        self.scan({'lib.js': 'export function f() { return req.query.html; }',
                   'app.js': 'import {f} from "./lib.js"; { const f = () => "safe"; res.send(f()); }'})
        self.scan({'lib.js': 'export function f() { return req.query.html; }',
                   'app.js': 'import * as lib from "./lib.js"; { const lib = {}; res.send(lib.f()); }'})

    def test_imported_callable_alias_uses_exporter_final_binding(self):
        self.scan({'lib.js': 'export let f = x => "safe"; f = external;',
                   'app.js': 'import {f} from "./lib.js"; const alias = f; res.send(alias(req.query.html));'}, ('app.js', 'xss'))
        self.scan({'lib.js': 'export function f() { return req.query.html; }',
                   'app.js': 'import * as lib from "./lib.js"; const alias = lib.f; res.send(alias());'}, ('app.js', 'xss'))

    def test_default_expression_is_evaluated_before_later_reassignment(self):
        self.scan({'lib.js': 'let f = x => x; export default f; f = x => "safe";',
                   'app.js': 'import f from "./lib.js"; res.send(f(req.query.html));'}, ('app.js', 'xss'))
        self.scan({'lib.js': 'let f = x => "safe"; export default f; f = x => x;',
                   'app.js': 'import f from "./lib.js"; res.send(f(req.query.html));'})

    def test_default_scalar_export(self):
        self.scan({'lib.js': 'export default req.query.html;',
                   'app.js': 'import html from "./lib.js"; res.send(html);'}, ('app.js', 'xss'))

    def test_cli_parallelism_keeps_import_components_together(self):
        with tempfile.TemporaryDirectory(prefix='ubs-modules-cli-') as tmp:
            root = Path(tmp).resolve()
            paths = self.write(root, {'lib.mjs': 'export function f(x) { res.send(x); }',
                                      'app.mjs': 'import {f} from "./lib.mjs"; f(req.query.html);',
                                      'other.mjs': 'const answer = 42;'})
            listing = root/'files'
            listing.write_bytes(b'\0'.join(os.fsencode(path) for path in paths)+b'\0')
            results = []
            for jobs in (1, 4):
                result = subprocess.run([sys.executable, '-m', 'ubs_core', 'taint', '--lang', 'javascript',
                                         '--files-from', str(listing), '--jobs', str(jobs)], cwd=tmp,
                                        env={**os.environ, 'PYTHONPATH':str(ROOT/'modules/helpers')},
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                records = [json.loads(line) for line in result.stdout.splitlines()]
                self.assertEqual(len(records), 1, (result.stdout, result.stderr))
                self.assertEqual(records[0]['path'], str(paths[0].resolve()))
                results.append(records)
            self.assertEqual(*results)

    def test_reexported_namespace_call(self):
        findings = self.scan({'lib.js': 'export function read() { return req.query.html; }',
                              'barrel.js': 'export * as api from "./lib.js";',
                              'app.js': 'import {api} from "./barrel.js"; res.send(api.read());'}, ('app.js', 'xss'))
        self.assertIn('lib.js:read()', findings[0]['message'])

    def test_nested_namespaces_and_callable_alias(self):
        self.scan({'lib.js': 'export function read() { return req.query.html; }',
                   'first.js': 'export * as api from "./lib.js";',
                   'second.js': 'export * as service from "./first.js";',
                   'app.js': 'import * as bundle from "./second.js"; const read = bundle.service.api.read; res.send(read());'}, ('app.js', 'xss'))

    def test_reexported_namespace_values(self):
        self.scan({'lib.js': 'export const box = {html: req.query.html, safe: "safe"};',
                   'barrel.js': 'export * as api from "./lib.js";',
                   'app.js': 'import {api} from "./barrel.js"; res.send(api.box.safe); eval(api.box.html);'}, ('app.js', 'eval'))

    def test_imported_namespace_reexported_as_default(self):
        self.scan({'lib.js': 'export function read() { return req.query.html; }',
                   'barrel.js': 'import * as api from "./lib.js"; export {api as default};',
                   'app.js': 'import api from "./barrel.js"; res.send(api.read());'}, ('app.js', 'xss'))

    def test_namespace_clean_function_is_not_argument_taint(self):
        self.scan({'lib.js': 'export function clean(x) { return "safe"; }',
                   'barrel.js': 'export * as api from "./lib.js";',
                   'app.js': 'import {api} from "./barrel.js"; res.send(api.clean(req.query.html));'})

    def test_namespace_shadow_keeps_unknown_argument_flow(self):
        self.scan({'lib.js': 'export function clean(x) { return "safe"; }',
                   'barrel.js': 'export * as api from "./lib.js";',
                   'app.js': 'import {api} from "./barrel.js"; function run(api) { res.send(api.clean(req.query.html)); }'}, ('app.js', 'xss'))

    def test_exported_live_scalar_write_and_cleanup(self):
        self.scan({'lib.js': 'export let x="safe"; export function set(v){x=v;}',
                   'app.js': 'import {set,x} from "./lib.js"; set(req.query.html); res.send(x);'}, ('app.js', 'xss'))
        self.scan({'lib.js': 'export let x=req.query.html; export function clear(){x="safe";}',
                   'app.js': 'import {clear,x} from "./lib.js"; clear(); res.send(x);'})

    def test_captured_imported_object_alias_changes_in_place(self):
        self.scan({'lib.js': 'export const box={html:"safe"}; export function set(v){box.html=v;}',
                   'app.js': 'import {set,box} from "./lib.js"; const alias=box; set(req.query.html); res.send(alias.html);'}, ('app.js', 'xss'))

    def test_cross_module_callable_write_invalidates_clean_summary(self):
        self.scan({'lib.js': 'export let f=x=>"safe"; export function set(){f=external;}',
                   'app.js': 'import {set,f} from "./lib.js"; set(); const alias=f; res.send(alias(req.query.html));'}, ('app.js', 'xss'))

    def test_callable_replacement_reaches_renamed_import(self):
        self.scan({'lib.js': 'export let f=x=>"safe"; export function set(){f=external;}',
                   'app.js': 'import {set,f as clean} from "./lib.js"; set(); res.send(clean(req.query.html));'}, ('app.js', 'xss'))

    def test_callable_replacement_reaches_namespace(self):
        self.scan({'lib.js': 'export let f=x=>"safe"; export function set(){f=external;}',
                   'app.js': 'import * as lib from "./lib.js"; lib.set(); res.send(lib.f(req.query.html));'}, ('app.js', 'xss'))

    def test_callable_replacement_reaches_nested_namespace_reexport(self):
        self.scan({'lib.js': 'export let f=x=>"safe"; export function set(){f=external;}',
                   'barrel.js': 'export * as api from "./lib.js";',
                   'app.js': 'import * as lib from "./barrel.js"; lib.api.set(); res.send(lib.api.f(req.query.html));'}, ('app.js', 'xss'))

    def test_single_file_entrypoint_preserves_export_initializers(self):
        with tempfile.TemporaryDirectory(prefix='ubs-module-single-') as tmp:
            paths = self.write(Path(tmp).resolve(), {'app.js': 'export const html=req.query.html; res.send(html);'})
            single = list(taint.scan_file_findings(paths[0]))
            project = list(taint.scan_project_findings(paths))
            self.assertEqual(single, [finding[1:] for finding in project])
            self.assertEqual([finding[0] for finding in single], ['js.taint.xss'])

    def test_provenance_distinguishes_same_named_files(self):
        findings = self.scan({'one/lib.js': 'export function read() { return req.query.html; }',
                              'two/lib.js': 'export function read() { return "safe"; }',
                              'app.js': 'import {read as a} from "./one/lib.js"; import {read as b} from "./two/lib.js"; res.send(a()); res.send(b());'}, ('app.js', 'xss'))
        self.assertIn('one/lib.js:read()', findings[0]['message'])

    def test_source_free_cyclic_modules_do_not_create_taint(self):
        self.scan({'a.js': 'export * from "./b.js";', 'b.js': 'export * from "./a.js";',
                   'app.js': 'import {unknown} from "./a.js"; res.send(unknown("safe"));'})

    def test_multiline_default_and_namespace_import(self):
        self.scan({'lib.js': 'export default function clean(x){return "safe";} export function read(){return req.query.html;}',
                   'app.js': 'import clean,\n* as api\nfrom "./lib.js";\nres.send(clean(req.query.html)); res.send(api.read());'}, ('app.js', 'xss'))

    def test_side_effect_import_cannot_hide_next_statement(self):
        self.scan({'lib.js': 'const answer = 42;',
                   'app.js': 'import "./lib.js";\nres.send(req.query.html);'}, ('app.js', 'xss'))

    def test_ambiguous_extension_does_not_choose_a_clean_candidate(self):
        self.scan({'lib.js': 'export function f(x){return "safe";}',
                   'lib.ts': 'export function f(x){return x;}',
                   'app.js': 'import {f} from "./lib"; res.send(f(req.query.html));'}, ('app.js', 'xss'))

    def test_sink_owner_cache_tracks_caller_and_selection(self):
        with tempfile.TemporaryDirectory(prefix='ubs-module-owner-cache-') as tmp:
            root = Path(tmp).resolve()
            paths = self.write(root, {'service/lib.js': 'export function output(x){res.send(x);}',
                                      'app.js': 'import {output} from "./service/lib.js"; output(req.query.html);'})
            listing, sink = root/'files', root/'sink'
            def scan(selected):
                listing.write_bytes(b'\0'.join(os.fsencode(path) for path in selected)+b'\0')
                js_scan.main(['--files-from',str(listing),'--sink',str(sink),'--project-dir',str(root)])
                return [r for line in sink.read_text().splitlines()
                        if (r:=json.loads(line))['rule'].startswith('javascript.taint.')]
            with mock.patch.dict(os.environ, {'UBS_CACHE_DIR':str(root/'cache'), 'UBS_NO_CACHE':'0'}):
                cold = scan(paths)
                self.assertEqual(len(cold), 1)
                self.assertEqual(cold[0]['path'],str(paths[0].resolve()))
                self.assertEqual(scan(paths), cold)
                paths[1].write_text('import {output} from "./service/lib.js"; output("safe");')
                self.assertEqual(scan(paths), [])
                self.assertEqual(scan([paths[0]]), [])
                paths[1].write_text('import {output} from "./service/lib.js"; output(req.query.html);')
                self.assertEqual(len(scan(paths)), 1)

    @unittest.skipUnless(shutil.which('node'), 'requires Node.js for independent semantic controls')
    def test_fixed_module_cases_agree_with_node_execution(self):
        cases = [
            ('export function f(){return req.query.html;}', 'res.send(f());', True),
            ('export function f(x){res.send(x);}', 'f(req.query.html);', True),
            ('export function f(x){return "safe";}', 'res.send(f(req.query.html));', False),
            ('export function f(box,x){box.html=x;}', 'const b={}; f(b,req.query.html); res.send(b.html);', True),
            ('export function f(box){box.html="safe";}', 'const b={html:req.query.html}; f(b); res.send(b.html);', False),
            ('export function f(x){return {html:x};}', 'const a=f(req.query.html); const b=f("safe"); res.send(b.html);', False),
            ('export function f(x){return {html:x};}', 'const a=f(req.query.html); res.send(a.html);', True),
            ('export let value="safe"; export function f(x){value=x;}', 'f(req.query.html); res.send(value);', True),
            ('export let value=req.query.html; export function f(){value="safe";}', 'const old=value; f(); res.send(old);', True),
            ('export let value=req.query.html; export function f(){value="safe";}', 'f(); res.send(value);', False),
        ]
        for number, (library, body, expected) in enumerate(cases):
            with self.subTest(number=number), tempfile.TemporaryDirectory(prefix='ubs-node-modules-') as tmp:
                root = Path(tmp).resolve()
                imports = 'f, value' if 'export let value' in library else 'f'
                paths = self.write(root, {'lib.mjs':library,
                                          'app.mjs':f'import {{{imports}}} from "./lib.mjs"; {body}'})
                program = ('globalThis.req={query:{html:"__UBS_INPUT__"}}; globalThis.out=[]; '
                           'globalThis.res={send:x=>out.push(x)}; '
                           f'await import({json.dumps(paths[1].as_uri())}); '
                           'console.log(JSON.stringify(out));')
                result = subprocess.run(['node','--input-type=module','-e',program],cwd=tmp,
                                        capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,(library,body,result.stdout,result.stderr))
                dynamic = '__UBS_INPUT__' in result.stdout
                self.assertEqual(dynamic,expected,(library,body,result.stdout,result.stderr))
                findings = list(taint.run(RunContext(lang='javascript',files=paths)))
                self.assertEqual(bool(findings),dynamic,(library,body,findings,result.stdout))

    @unittest.skipUnless(shutil.which('ast-grep'), 'requires ast-grep for the actual meta-runner')
    def test_meta_runner_cross_module_flows(self):
        cases = [
            ('source','export function f(){return req.query.html;}','res.send(f());',('app.mjs','xss')),
            ('sink','export function f(x){res.send(x);}','f(req.query.html);',('lib.mjs','xss')),
            ('clean','export function f(x){return "safe";}','res.send(f(req.query.html));',None),
            ('mutation','export function f(b,x){b.html=x;}','const b={};f(b,req.query.html);res.send(b.html);',('app.mjs','xss')),
            ('cleanup','export function f(b){b.html="safe";}','const b={html:req.query.html};f(b);res.send(b.html);',None),
        ]
        for name,library,body,expected in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix='ubs-modules-e2e-') as tmp:
                root=Path(tmp).resolve()
                paths=self.write(root,{'lib.mjs':library,'app.mjs':'import {f} from "./lib.mjs"; '+body})
                result=subprocess.run([str(ROOT/'ubs'),*(str(p) for p in paths),'--only=js','--format=json','--ci'],
                                      cwd=tmp,capture_output=True,text=True,timeout=120,
                                      env={**os.environ,'UBS_NO_AUTO_UPDATE':'1','UBS_NO_CACHE':'1'})
                artifact=ROOT/'test-suite/artifacts/javascript-modules'/name
                artifact.mkdir(parents=True,exist_ok=True)
                (artifact/'stdout.log').write_text(result.stdout)
                (artifact/'stderr.log').write_text(result.stderr)
                self.assertIn(result.returncode,(0,1),(result.stdout,result.stderr))
                report=json.loads(result.stdout)
                (artifact/'result.json').write_text(json.dumps(report,indent=2))
                self.assert_report_findings(report, root, expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
