"""Issue #169: source-aware Task.Result findings and conservative fallback."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "helpers"))

from ubs_core.csharp_patterns._result import result_lines  # noqa: E402

REPRO = '''using System.Threading.Tasks;

public sealed record Outcome(string Result);

public static class Repro
{
    // 1. A record's own string property named Result: not a Task.
    public static string FromRecord(Outcome o) => o.Result;

    // 2. A tuple element named Result: not a Task.
    static (int Code, string Result) Pair() => (0, "ok");
    public static string FromTuple() => Pair().Result;

    // 3. A real Task<int>.Result: the only genuine blocking call.
    public static int Blocking(Task<int> t) => t.Result;
}
'''


class ResultReceiverTests(unittest.TestCase):
    def test_reporter_example(self):
        self.assertEqual(({15}, set()), result_lines(REPRO))

    def test_clean_reporter_members_without_task(self):
        source = REPRO.replace('    public static int Blocking(Task<int> t) => t.Result;\n', '')
        self.assertEqual((set(), set()), result_lines(source))

    def test_comment_and_literal_decoys(self):
        source = '''class C {
// task.Result
/* task.Result
 * another.Result */
string a = "task.Result";
string b = @"task.Result";
string c = """ task.Result """;
string d = $"task.Result";
char e = '.';
}'''
        self.assertEqual((set(), set()), result_lines(source))

    def test_task_receiver_forms(self):
        expressions = ('t.Result', '(t).Result', 't!.Result', 't?.Result',
                       'Task.FromResult(1).Result', 'Task.Run(() => 1).Result',
                       'new Task<int>(() => 1).Result', 'v.Result', 'v.AsTask().Result',
                       'Get().Result', '((Task<int>)obj).Result')
        for expression in expressions:
            with self.subTest(expression=expression):
                source = ('using System.Threading.Tasks; class C { '
                          'static Task<int> Get() => Task.FromResult(1); '
                          'void M(Task<int> t, ValueTask<int> v, object obj) { '
                          f'var x = {expression};' + ' }}')
                self.assertEqual(({1}, set()), result_lines(source))

    def test_alias_and_qualified_types(self):
        for declaration in ('global::System.Threading.Tasks.Task<int> t',
                            'System.Threading.Tasks.ValueTask<int> t', 'Work t'):
            with self.subTest(declaration=declaration):
                source = ('using Work = System.Threading.Tasks.Task<int>; '
                          f'class C {{ int M({declaration}) => t.Result; }}')
                self.assertEqual(({1}, set()), result_lines(source))

    def test_var_local_and_tuple_initializer(self):
        source = '''using System.Threading.Tasks;
record Outcome(string Result);
class C { void M() {
var response = new Outcome("ok");
var a = response.Result;
var tuple = (Result: "ok", Count: 1);
var b = tuple.Result;
var task = Task.FromResult(1);
var c = task.Result;
} }'''
        self.assertEqual(({9}, set()), result_lines(source))

    def test_same_name_in_separate_scopes(self):
        source = '''using System.Threading.Tasks;
record Outcome(string Result);
class C {
string Good(Outcome value) => value.Result;
int Bad(Task<int> value) => value.Result;
}'''
        self.assertEqual(({5}, set()), result_lines(source))

    def test_local_task_named_record_is_not_bcl(self):
        source = '''using System.Threading.Tasks;
record Task<T>(T Result);
class C { int M(Task<int> t) => t.Result; }'''
        self.assertEqual((set(), set()), result_lines(source))

    def test_primary_constructor_parameters_shadow_types_and_keep_task_identity(self):
        source = '''using System.Threading.Tasks;
record Outcome(string Result);
class C(Outcome Task, Task<int> work) {
string Safe() => Task.Result;
int Blocking() => work.Result;
}'''
        self.assertEqual(({5}, set()), result_lines(source))

    def test_unknown_receiver_is_not_silently_clean(self):
        source = 'class C { object M(dynamic value) => value.Result; }'
        self.assertEqual((set(), {1}), result_lines(source))
        self.assertEqual((set(), {1}), result_lines('var x = GetElsewhere().Result;'))

    def test_unrelated_method_name_does_not_prove_tuple(self):
        source = '''class A { (int Code, string Result) Pair() => (0, "ok"); }
class B { object M() => Pair().Result; }'''
        self.assertEqual((set(), {2}), result_lines(source))

    def test_task_in_interpolation_is_executable(self):
        source = '''using System.Threading.Tasks;
class C { string M(Task<int> t) => $"inert.Result {t.Result}"; }'''
        self.assertEqual(({2}, set()), result_lines(source))

    def test_nameof_is_not_a_getter_invocation(self):
        source = 'using System.Threading.Tasks; class C { string M(Task<int> t) => nameof(t.Result); }'
        self.assertEqual((set(), set()), result_lines(source))

    def test_task_array_and_chained_record_member(self):
        source = '''using System.Threading.Tasks;
record Holder(Task<int> Result);
class C {
int A(Task<int>[] tasks) => tasks[0].Result;
int B(Holder h) => h.Result.Result;
}'''
        self.assertEqual(({4, 5}, set()), result_lines(source))

    def test_multiline_member_access(self):
        source = '''using System.Threading.Tasks;
class C { int M(Task<int> t) => t
.
Result; }'''
        self.assertEqual(({4}, set()), result_lines(source))

    def test_lambda_shadow_does_not_reuse_outer_type(self):
        source = '''record Outcome(string Result);
class C { void M(Outcome value) { Use(value => value.Result); } }'''
        self.assertEqual((set(), {2}), result_lines(source))

    def test_conditional_bindings_stay_conservative(self):
        source = '''record Outcome(string Result);
#if ONE
Outcome value;
#else
Task<int> value;
#endif
var x = value.Result;'''
        self.assertEqual((set(), {7}), result_lines(source))

    def test_task_aliases_fields_and_arguments_remain_critical(self):
        expressions = (
            'var alias = t; Use(alias.Result);',
            'Use(1, t.Result);',
            'Use(this.task.Result);',
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                source = ('using System.Threading.Tasks; class C { Task<int> task; '
                          'void M(Task<int> t) { ' + expression + ' }}')
                self.assertEqual(({1}, set()), result_lines(source))

    def test_local_function_cannot_prove_an_unrelated_call_safe(self):
        source = ('class C { void A() { (int Code, string Result) Pair() => (0, "ok"); } '
                  'object B() => Pair().Result; }')
        self.assertEqual((set(), {1}), result_lines(source))

    def test_malformed_input_does_not_erase_findings(self):
        self.assertEqual((set(), {1}), result_lines('void Broken( { task.Result;'))


UNRESOLVED = '''class C {
    object A(dynamic value) => value.Result;
    object B() => GetElsewhere()
        .Result;
}
'''


class AstPackResultTests(unittest.TestCase):
    """The ast-grep pack's type-blind `$TASK.Result` rule follows the same receivers."""

    def setUp(self):
        artifacts = ROOT / 'test-suite' / 'artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        self.folder = Path(tempfile.mkdtemp(prefix='csharp-ast-result-', dir=artifacts))

    def ast_lines(self, sources):
        from ubs_core.cache import CapturingSink
        from ubs_core.csharp_ast import scan_all
        from ubs_core.csharp_patterns._result import ast_result_qualifier
        from ubs_core.csharp_rules import generate

        generate(self.folder / 'pack')
        texts = {}
        for name, source in sources.items():
            path = self.folder / name
            path.write_text(source, encoding='utf-8')
            texts[path] = source
        sink, errors = CapturingSink(), []
        scan_all(self.folder / 'pack', list(texts), sink, errors=errors,
                 qualify=ast_result_qualifier(texts))
        self.assertEqual(errors, [])
        return {Path(key).name: sorted(record['line'] for record in records
                                       if record['rule'] == 'cs-task-result-deadlock')
                for key, records in sink.by_file.items()}

    def test_record_and_tuple_members_are_not_task_results(self):
        lines = self.ast_lines({'Repro.cs': REPRO, 'Unresolved.cs': UNRESOLVED})
        self.assertEqual(lines['Repro.cs'], [15])
        # Unresolved receivers stay visible, including one whose `.Result`
        # token is on a later line than the start of its receiver.
        self.assertEqual(lines['Unresolved.cs'], [2, 3])

    def test_public_scan_reports_only_the_task_result(self):
        target = self.folder / 'Repro.cs'
        target.write_text(REPRO, encoding='utf-8')
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('UBS_', 'XDG_'))}
        env.update(UBS_NO_AUTO_UPDATE='1', UBS_NO_CACHE='1', PYTHONDONTWRITEBYTECODE='1',
                   NO_COLOR='1', XDG_DATA_HOME=str(self.folder / 'data'),
                   XDG_CACHE_HOME=str(self.folder / 'cache'))
        command = [str(ROOT / 'ubs'), '--no-config', '--only=csharp', '--ci', '--no-cache',
                   '--format=json', str(target)]
        result = subprocess.run(command, cwd=self.folder, env=env, capture_output=True,
                                text=True, timeout=180, check=False)
        details = f'{command!r}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}'
        self.assertEqual(result.returncode, 1, details)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'ok', details)
        observed = sorted((finding['rule'], finding['line'])
                          for scanner in report['scanners'] for finding in scanner['findings']
                          if finding['rule'] in {'cs.pattern.blocking-result',
                                                 'cs.pattern.possible-blocking-result',
                                                 'cs-task-result-deadlock'})
        self.assertEqual(observed, [('cs-task-result-deadlock', 15),
                                    ('cs.pattern.blocking-result', 15)], details)


if __name__ == '__main__':
    unittest.main()
