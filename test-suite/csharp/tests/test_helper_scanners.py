#!/usr/bin/env python3
"""Regression tests for the C# helper analyzers."""
from __future__ import annotations

import os
import json
import hashlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TYPE_HELPER = REPO_ROOT / "modules" / "helpers" / "type_narrowing_csharp.py"
RESOURCE_HELPER = REPO_ROOT / "modules" / "helpers" / "resource_lifecycle_csharp.py"
ASYNC_HELPER = REPO_ROOT / "modules" / "helpers" / "async_task_handles_csharp.py"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO_ROOT / "modules" / "helpers"))

from ubs_core.analyzers.narrowing_csharp import scan_text  # noqa: E402


GUARD_REPRO = '''using System;
public static class Guards {
    public static string CommentBeforeReturn(decimal? p) {
        if (p == null)
            // nothing printed
            return "";
        return p.Value.ToString("0.00");
    }
    public static string GotoExit(decimal? p) {
        if (p == null) goto done;
        return p.Value.ToString("0.00");
    done:
        return "";
    }
    public static string GuardedUse(decimal? p) {
        if (p == null) Console.WriteLine("missing");
        return p.HasValue ? p.Value.ToString("0.00") : "";
    }
    public static string Unsafe(decimal? p) {
        if (p == null) { Console.WriteLine("missing"); }
        return p.Value.ToString("0.00"); // expect-negative
    }
}
'''

RETHROW_REPRO = '''using System;
class Exceptions {
    void NewOutside() { throw new InvalidOperationException("new"); }
    void Check(int tier) { if (tier < 0) throw new ArgumentOutOfRangeException(nameof(tier)); }
    void Caught() {
        try { Work(); }
        catch (Exception ex) { throw ex; } // expect-rethrow
    }
    void Wrapped() {
        try { Work(); }
        catch (Exception ex) { throw new InvalidOperationException("wrap", ex); }
    }
    void Preserved() {
        try { Work(); }
        catch (Exception) { throw; }
    }
    void Unrelated(Exception other) {
        try { Work(); }
        catch (Exception ex) { throw other; }
    }
    void Nested(bool flag) {
        try { Work(); }
        catch (Exception outer) {
            if (flag) { throw outer; } // expect-rethrow
            try { Work(); }
            catch (Exception inner) {
                if (flag) throw inner; // expect-rethrow
                throw outer;
            }
        }
    }
    void Deferred() {
        try { Work(); }
        catch (Exception ex) {
            void Later(Exception ex) { throw ex; }
            Action action = () => { throw ex; };
            Action<Exception> other = ex => { throw ex; };
            Action legacy = delegate { throw ex; };
        }
    }
    void FinallyBoundary() {
        try { Work(); }
        catch (Exception ex) {
            try { Work(); }
            finally {
                throw ex;
            }
        }
    }
    void CatchWithinFinally() {
        try { Work(); }
        finally {
            try { Work(); }
            catch (Exception ex) { throw ex; } // expect-rethrow
        }
    }
    void ReplacementIdentity() {
        try { Work(); }
        catch (Exception ex) {
            ex = new InvalidOperationException();
            throw ex; // expect-rethrow: recommendation is conditional on exception identity
        }
    }
    void UnknownReplacement() {
        try { Work(); }
        catch (Exception ex) {
            Replace(ref ex);
            throw ex; // expect-rethrow: recommendation is conditional on exception identity
        }
    }
    void Decoys() {
        // catch (Exception ex) { throw ex; }
        var text = "catch (Exception ex) { throw ex; }";
        var raw = """catch (Exception ex) { throw ex; }""";
    }
}
'''

GUARD_SCOPE_REPRO = '''using System;
class Scopes {
    string p;
    Scopes(string p) { if (p == null) Log(); Use(p.Length); } // expect-negative
    int Read { get { if (p == null) Log(); return p.Length; } } // expect-negative
    string Write { set { if (value == null) Log(); Use(value.Length); } } // expect-value
    string Init { init { if (value == null) Log(); Use(value.Length); } } // expect-value
    void Callbacks() {
        Action<string> f = (string p) => { if (p == null) Log(); Use(p.Length); }; // expect-negative
        Action<string> g = delegate(string p) { if (p == null) Log(); Use(p.Length); }; // expect-negative
    }
    void Capture(decimal? p) {
        Action f = () => { if (p == null) Log(); Use(p.HasValue ? p.Value : 0); };
    }
    void CaptureLocal() {
        decimal? p = null;
        Action f = () => { if (p == null) Log(); Use(p.HasValue ? p.Value : 0); };
    }
}
'''

UNSUPPORTED_GUARD_SCOPES = (
    'class C { string p; public static C operator +(C p, C q) { if (p == null) Log(); Use(p.p.Length); return q; } }',
    'class C { void Run(string p) { if (p == null) return; try { Work(); } catch (Exception e) when ((p = null) == null) {} Use(p.Length); } }',
)


def run_helper(helper: Path, sources: dict[str, str]) -> list[str]:
    temp_dir = Path(tempfile.mkdtemp(prefix="ubs-csharp-helper-"))
    try:
        for rel, code in sources.items():
            path = temp_dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(code), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(helper), str(temp_dir)],
            capture_output=True,
            text=True,
            check=False,
            # An AST helper over a handful of fixture files takes a second or
            # two; without a deadline a hung helper hangs the suite with no
            # diagnostic (#123). An expiry raises, which is a failure.
            timeout=int(os.environ.get("UBS_TEST_CHILD_TIMEOUT", "120")),
        )
        return [line for line in result.stdout.splitlines() if line.strip()]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


class CSharpHelperTests(unittest.TestCase):
    def test_reviewed_expression_effects_and_runtime_dereferences(self) -> None:
        cases = (
            ('string p', 'if(p==null)return; string q=null; var x=q??(p=null); Use(p.Length);', 'p.Length'),
            ('string p', 'if(p==null)Log(); var x=p??(p="safe"); Use(p.Length);', None),
            ('string p', 'if(p==null)return; var x=p??(p=null); Use(p.Length);', None),
            ('string p', 'if(p==null)return; Clear(ref p); Use(p.Length);', 'p.Length'),
            ('string p', 'if(p==null)return; Clear(out p); Use(p.Length);', 'p.Length'),
            ('string p', 'if(p==null)return; Inspect(in p); Use(p.Length);', None),
            ('string p', 'if(p==null)Log(); return p!;', None),
            ('string p', 'if(p==null)Log(); Use(p!.Length);', 'p!.Length'),
            ('string p', 'if(p==null)Log(); Use((p).Length);', 'p).Length'),
            ('string p', 'if(p==null)Log(); Use((p!).Length);', 'p!).Length'),
            ('decimal? p, decimal? q', 'if(p==null)return; p=1+q; Use(p.Value);', 'p.Value'),
            ('bool? p, bool? q', 'if(p==null)return; p=true & q; Use(p.Value);', 'p.Value'),
            ('string p', 'if(p==null)return; p=new object() as string; Use(p.Length);', 'p.Length'),
            ('string p', 'if(p==null)return; p=new string[]{null}[0]; Use(p.Length);', 'p.Length'),
            ('string p', 'if(p==null)Log(); p=new string(new[]{\'x\'}); Use(p.Length);', None),
            ('decimal? p', 'if(p==null)Log(); p=42m; Use(p.Value);', None),
            ('bool? p', 'if(p==null)Log(); p=true; Use(p.Value);', None),
        )
        for parameters, body, target in cases:
            source = f'class C {{ void Run({parameters}) {{ {body} }} }}'
            with self.subTest(source=source):
                expected = [("negative_guard", 1, source.index(target) + 1,
                             "p dereferenced after non-exiting null/empty guard")] if target else []
                self.assertEqual(scan_text(source), expected)

    def test_explicit_this_field_identity_and_local_shadowing(self) -> None:
        cases = (
            ('', 'if(p==null)return; this.p=null; Use(p.Length);', 'p.Length', 'p'),
            ('', 'if(p==null)Log(); Use(this.p.Length);', 'this.p.Length', 'this.p'),
            ('', 'if(this.p==null)return; p=null; Use(this.p.Length);', 'this.p.Length', 'this.p'),
            ('string p', 'if(p==null)return; this.p=null; Use(p.Length);', None, ''),
            ('string p', 'if(this.p==null)Log(); p="safe"; Use(this.p.Length);', 'this.p.Length', 'this.p'),
        )
        for parameters, body, target, name in cases:
            source = f'class C {{ string p; void Run({parameters}) {{ {body} }} }}'
            with self.subTest(source=source):
                expected = [("negative_guard", 1, source.index(target) + 1,
                             f"{name} dereferenced after non-exiting null/empty guard")] if target else []
                self.assertEqual(scan_text(source), expected)

    def test_constructor_accessor_callback_and_captured_type_scopes(self) -> None:
        expected = []
        for number, line in enumerate(GUARD_SCOPE_REPRO.splitlines(), 1):
            name = "value" if "expect-value" in line else "p" if "expect-negative" in line else None
            if name:
                expected.append(("negative_guard", number, line.index(name + ".Length") + 1,
                                 f"{name} dereferenced after non-exiting null/empty guard"))
        self.assertEqual(scan_text(GUARD_SCOPE_REPRO), expected)
        safe = GUARD_SCOPE_REPRO.replace('if (p == null) Log();', 'if (p == null) throw new Exception();')
        safe = safe.replace('if (value == null) Log();', 'if (value == null) throw new Exception();')
        self.assertEqual(scan_text(safe), [])
        nullable_setter = 'class C { decimal? P { set { if(value==null)Log(); Use(value.HasValue ? value.Value : 0); } } }'
        self.assertEqual(scan_text(nullable_setter), [])
        captured_shadow = ('class C { decimal? p; void Run(Cell[] cells) { foreach(Cell p in cells) {'
                           'Action f = () => { if(p==null)Log(); Use(p.HasValue ? p.Value : 0); }; } } }')
        self.assertEqual([finding[2] for finding in scan_text(captured_shadow)],
                         [captured_shadow.index(expression) + 1 for expression in ('p.HasValue', 'p.Value')])

    def test_scoped_null_guard_control_flow_and_expressions(self) -> None:
        cases = (
            ("conditional_return", 'if (p == null) { if (flag) return ""; } return p.Value.ToString();', True),
            ("all_branches_exit", 'if (p == null) { if (flag) return ""; else throw new Exception(); } return p.Value.ToString();', False),
            ("nested_function_return", 'if (p == null) { void Later() { return; } Log(); } return p.Value.ToString();', True),
            ("nested_lambda_return", 'if (p == null) { Action later = () => { return; }; } return p.Value.ToString();', True),
            ("comment_is_not_exit", 'if (p == null) { /* return; */ Log(); } return p.Value.ToString();', True),
            ("literal_is_not_exit", 'if (p == null) { Log("return; throw; }"); } return p.Value.ToString();', True),
            ("block_comment_before_return", 'if (p == null) /*\n ignore; }\n */ return ""; return p.Value.ToString();', False),
            ("goto_skips_unsafe_statement", 'if (p == null) goto done; return p.Value.ToString(); done: return "";', False),
            ("goto_lands_on_unsafe_statement", 'if (p == null) goto done; Log(); done: return p.Value.ToString();', True),
            ("goto_out_of_nested_block", '{ if (p == null) goto done; Log(); } return p.Value.ToString(); done: return "";', False),
            ("goto_backedge_preserves_null", 'again: if (p == null) { if (flag) goto again; } return p.Value.ToString();', True),
            ("has_value_ternary", 'if (p == null) Log(); return p.HasValue ? p.Value.ToString() : "";', False),
            ("has_value_else_unsafe", 'if (p == null) Log(); return p.HasValue ? "ok" : p.Value.ToString();', True),
            ("has_value_and", 'if (p == null) Log(); return (p.HasValue && p.Value > 0).ToString();', False),
            ("has_value_or_unsafe", 'if (p == null) Log(); return (p.HasValue || p.Value > 0).ToString();', True),
            ("not_has_value_or", 'if (p == null) Log(); return (!p.HasValue || p.Value > 0).ToString();', False),
            ("null_comparison_ternary", 'if (p == null) Log(); return p != null ? p.Value.ToString() : "";', False),
            ("null_pattern_ternary", 'if (p == null) Log(); return p is not null ? p.Value.ToString() : "";', False),
            ("reverse_null_ternary", 'if (p == null) Log(); return null == p ? "" : p.Value.ToString();', False),
            ("unrelated_has_value", 'if (p == null) Log(); return q.HasValue ? p.Value.ToString() : "";', True),
            ("conditional_access", 'if (p == null) Log(); return p?.ToString();', False),
            ("safe_nullable_methods", 'if (p == null) Log(); return p.ToString() + p.GetValueOrDefault().ToString();', False),
            ("name_of_not_executed", 'if (p == null) Log(); return nameof(p.Value);', False),
            ("literal_dereference_decoy", 'if (p == null) Log(); return "p.Value";', False),
            ("raw_literal_dereference_decoy", 'if (p == null) Log(); return """p.Value""";', False),
            ("interpolation_executes_dereference", 'if (p == null) Log(); return $"value: {p.Value}";', True),
            ("raw_interpolation_executes_dereference", 'if (p == null) Log(); return $$"""value: {{p.Value}}""";', True),
            ("literal_assignment_repairs", 'if (p == null) Log(); p = 42; return p.Value.ToString();', False),
            ("branch_assignment_repairs", 'if (p == null) p = 42; return p.Value.ToString();', False),
            ("partial_assignment_does_not_repair", 'if (p == null) Log(); if (flag) p = 42; return p.Value.ToString();', True),
            ("null_assignment_invalidates_guard", 'if (p == null) return ""; p = null; return p.Value.ToString();', True),
            ("callback_assignment_does_not_repair", 'if (p == null) { Action later = () => { p = 42; }; } return p.Value.ToString();', True),
            ("equality_is_not_assignment", 'if (p == null) Log(); Log(p == null); return p.Value.ToString();', True),
            ("continue_exits_only_iteration", 'while (flag) { if (p == null) continue; Log(p.Value); } return "";', False),
            ("break_leaves_nullable_after_loop", 'while (true) { if (p == null) break; return ""; } return p.Value.ToString();', True),
            ("inner_break_is_not_guard_exit", 'if (p == null) { while (flag) { break; } } return p.Value.ToString();', True),
            ("finally_invalidates_guard", 'if (p == null) return ""; try { Log(); } finally { p = null; } return p.Value.ToString();', True),
            ("caught_throw_is_not_exit", 'if (p == null) { try { throw new Exception(); } catch (Exception e) { Log(e); } } return p.Value.ToString();', True),
            ("unconditional_throw_exits", 'if (p == null) { Log(); throw new Exception(); } return p.Value.ToString();', False),
        )
        for name, body, unsafe in cases:
            with self.subTest(case=name):
                source = 'using System; class C { string Run(decimal? p, decimal? q, bool flag) {\n' + body + '\n} }'
                observed = scan_text(source)
                position = source.index("p.Value") if "p.Value" in source else -1
                if unsafe:
                    prefix = source[:position]
                    expected = [("negative_guard", prefix.count("\n") + 1,
                                 position - prefix.rfind("\n"),
                                 "p dereferenced after non-exiting null/empty guard")]
                else:
                    expected = []
                self.assertEqual(observed, expected, source)

    def test_guard_names_do_not_leak_between_functions_or_bindings(self) -> None:
        source = '''record Cell(decimal Value);
        class C {
            decimal? p;
            void Inspect(decimal? p) { if (p == null) Log(); }
            decimal Read(Cell p) { return p.Value; }
            void Local(decimal? p) {
                if (p == null) Log();
                decimal Read(Cell value) { return value.Value; }
                Use(p => p.Value);
            }
            void Blocks() {
                if (p == null) Log();
                { Cell p = new Cell(42); Use(p.Value); }
            }
        }'''
        self.assertEqual(scan_text(source), [])

    def test_nullable_fields_and_reference_has_value_stay_distinct(self) -> None:
        source = '''class C {
            decimal? p;
            decimal Read() { if (p == null) Log(); return p.HasValue ? p.Value : 0; }
            decimal Other(Cell p) {
                if (p == null) Log();
                return p.HasValue ? p.Value : 0;
            }
        }'''
        findings = scan_text(source)
        line = source.splitlines()[5]
        self.assertEqual(findings, [("negative_guard", 6, line.index(expression) + 1,
                                     "p dereferenced after non-exiting null/empty guard")
                                    for expression in ("p.HasValue", "p.Value")])

    def test_has_value_proof_requires_nullable_value_type_identity(self) -> None:
        cases = (
            ("", "decimal?", False),
            ("", "System.Nullable<decimal>", False),
            ("", "global::System.Nullable<decimal>", False),
            ("class DateTime { public bool HasValue; public decimal Value; }", "DateTime?", True),
            ("class Guid { public bool HasValue; public decimal Value; }", "Guid?", True),
            ("class Nullable<T> { public bool HasValue; public decimal Value; }", "Nullable<decimal>", True),
            ("class System { public class Nullable<T> { public bool HasValue; public decimal Value; } }", "System.Nullable<decimal>", True),
            ("namespace System { public class Nullable<T> { public bool HasValue; public decimal Value; } }", "global::System.Nullable<decimal>", True),
            ("interface System { interface Nullable<T> { bool HasValue {get;} decimal Value {get;} } }", "System.Nullable<decimal>", True),
        )
        for declaration, spelling, unsafe in cases:
            with self.subTest(spelling=spelling, declaration=declaration):
                source = declaration + '\nclass C { decimal Read(' + spelling + ' p) { if (p == null) Log(); return p.HasValue ? p.Value : 0; } }'
                line = source.splitlines()[1]
                expected = [("negative_guard", 2, line.index(expression) + 1,
                             "p dereferenced after non-exiting null/empty guard")
                            for expression in ("p.HasValue", "p.Value")] if unsafe else []
                self.assertEqual(scan_text(source), expected)

    def test_field_shadowing_and_unrelated_member_assignment(self) -> None:
        source = '''class C {
            string p;
            void Read(C other) {
                if (p == null) Log();
                foreach (var p in new[] { "safe" }) { Use(p.Length); }
                try { Work(); } catch (Exception p) { Use(p.Message); }
                other.p = "safe";
                Use(p.Length);
            }
        }'''
        self.assertEqual(scan_text(source), [("negative_guard", 8, 21,
                                             "p dereferenced after non-exiting null/empty guard")])

    def test_positive_guard_alternate_exit_and_fallthrough(self) -> None:
        for alternate, expected in (("else return 0;", []), ("", ["positive_guard"])):
            with self.subTest(alternate=alternate):
                source = ('class C { int Run(string p) { if (p != null) { return p.Length; } '
                          + alternate + ' return p.Length; } }')
                self.assertEqual([finding[0] for finding in scan_text(source)], expected)

    def test_unrelated_control_flow_does_not_activate_null_analysis(self) -> None:
        sources = (
            'class C { void Run(int x) { switch(x) { case 1: goto case 2; case 2: break; } } }',
            'class C { C(decimal? p) {} void Run(int x) { if (x > 0) Work(null); switch(x) { case 1: goto default; default: break; } } }',
            'class C { void Run(int x) { var example = "if (p == null) Log();"; switch(x) { case 1: goto case 2; case 2: break; } } }',
            'class C { void Run(int x) { if (x > 0) Work(null);\n#if FEATURE\nLog();\n#endif\n} }',
            'class C { void Run(int x) { var example = "if (p == null) Log();";\n#if FEATURE\nLog();\n#endif\n} }',
            'class C { void Other(int x) { switch(x) { case 1: goto case 2; case 2: break; } } int Run(string p) { if (p == null) return 0; return p.Length; } }',
            'class C { public static C operator +(C p, C q) { if (true) Log(); return q; } }',
            'class C { void Run(string p) { try { Work(); } catch(Exception e) when((p=null)==null){} } }',
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(scan_text(source), [])

    def test_selected_unsupported_flow_and_malformed_guards_are_explicit(self) -> None:
        sources = UNSUPPORTED_GUARD_SCOPES + (
            'class C { int Run(string p, int x) { if(p == null) Log(); switch(x) { case 1: goto case 2; case 2: break; } return p.Length; } }',
            'class C { int Run(string p) { if(p == null) goto missing; return p.Length; } }',
            'class C { int Run(string p) { if(p == null) Log();\n#if FEATURE\np = "safe";\n#endif\nreturn p.Length; } }',
            'class C { int Run(string p) { if(p == null) { Log(); return p.Length; }',
        )
        for source in sources:
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "incomplete"):
                scan_text(source)

    def test_reported_negative_guards_have_one_unsafe_use(self) -> None:
        expected = [("negative_guard", number, line.index("p.Value") + 1,
                     "p dereferenced after non-exiting null/empty guard")
                    for number, line in enumerate(GUARD_REPRO.splitlines(), 1)
                    if "// expect-negative" in line]
        self.assertEqual(scan_text(GUARD_REPRO), expected)

    @unittest.skipUnless(shutil.which("ast-grep"), "real ast-grep is required")
    def test_rethrow_pack_matches_the_active_catch_binding(self) -> None:
        from ubs_core.csharp_rules import generate

        artifacts = REPO_ROOT / "test-suite" / "artifacts" / "csharp-semantics"
        artifacts.mkdir(parents=True, exist_ok=True)
        folder = Path(tempfile.mkdtemp(prefix="rethrow-", dir=artifacts))
        target = folder / "Exceptions.cs"
        target.write_text(RETHROW_REPRO, encoding="utf-8")
        generate(folder / "pack")
        command = [shutil.which("ast-grep"), "scan", "-c",
                   str(folder / "pack" / "sgconfig-csharp.yml"),
                   "--filter", "^cs-rethrow-ex$", "--json", str(target)]
        result = subprocess.run(command, cwd=folder, capture_output=True,
                                text=True, timeout=30, check=False)
        (folder / "stdout.json").write_text(result.stdout, encoding="utf-8")
        (folder / "stderr.log").write_text(result.stderr, encoding="utf-8")
        details = f"{command!r}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        self.assertIn(result.returncode, (0, 1), details)
        try:
            findings = json.loads(result.stdout)
        except ValueError as exc:
            self.fail(f"invalid ast-grep JSON: {exc}\n{details}")
        observed = sorted((item["ruleId"], item["range"]["start"]["line"] + 1,
                           item["range"]["start"]["column"] + 1) for item in findings)
        expected = [("cs-rethrow-ex", number, line.index("throw ") + 1)
                    for number, line in enumerate(RETHROW_REPRO.splitlines(), 1)
                    if "// expect-rethrow" in line]
        self.assertEqual(observed, expected, details)
        self.assertTrue(all("If this variable still refers to the currently handled exception" in item["message"]
                            for item in findings), details)

    def test_type_narrowing_helper_reports_guard_fallthrough(self) -> None:
        lines = run_helper(
            TYPE_HELPER,
            {
                "buggy.cs": """
                using System;
                using System.Collections.Generic;

                class Demo {
                    int Run(string rawInput, Dictionary<string, string> cache) {
                        if (rawInput == null) {
                            Console.WriteLine("missing");
                        }
                        if (!cache.TryGetValue("token", out var token)) {
                            Console.WriteLine("missing token");
                        }
                        return rawInput.Trim().Length + token.Length;
                    }
                }
                """,
            },
        )
        self.assertTrue(any("rawInput dereferenced after non-exiting null/empty guard" in line for line in lines))
        self.assertTrue(any("token used after non-exiting TryGetValue guard" in line for line in lines))

    def test_type_narrowing_helper_stays_quiet_for_clean_guards(self) -> None:
        lines = run_helper(
            TYPE_HELPER,
            {
                "clean.cs": """
                using System.Collections.Generic;

                class Demo {
                    int? Run(string rawInput, Dictionary<string, string> cache) {
                        if (string.IsNullOrWhiteSpace(rawInput)) {
                            return null;
                        }
                        if (!cache.TryGetValue("token", out var token)) {
                            return null;
                        }
                        return rawInput.Trim().Length + token.Length;
                    }
                }
                """,
            },
        )
        self.assertEqual(lines, [])

    def test_resource_helper_reports_disposable_leaks(self) -> None:
        lines = run_helper(
            RESOURCE_HELPER,
            {
                "leaky.cs": """
                using System.IO;
                using System.Net.Http;
                using System.Threading;

                class Demo {
                    void Leak() {
                        var cts = new CancellationTokenSource();
                        var reader = new StreamReader(new MemoryStream());
                        var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com");
                    }
                }
                """,
            },
        )
        self.assertTrue(any("CancellationTokenSource acquired without Dispose" in line for line in lines))
        self.assertTrue(any("Stream-like handle acquired without using/Dispose/Close" in line for line in lines))
        self.assertTrue(any("HttpRequestMessage created without Dispose" in line for line in lines))

    def test_resource_helper_ignores_using_var_cleanup(self) -> None:
        lines = run_helper(
            RESOURCE_HELPER,
            {
                "clean.cs": """
                using System.IO;
                using System.Net.Http;
                using System.Threading;

                class Demo {
                    void Tidy() {
                        using var cts = new CancellationTokenSource();
                        using var reader = new StreamReader(new MemoryStream());
                        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com");
                    }
                }
                """,
            },
        )
        self.assertEqual(lines, [])

    def test_async_helper_reports_unobserved_task_handles(self) -> None:
        lines = run_helper(
            ASYNC_HELPER,
            {
                "buggy.cs": """
                using System.Threading.Tasks;

                class Demo {
                    void Run() {
                        var pending = Task.Run(() => 42);
                    }
                }
                """,
            },
        )
        self.assertTrue(any("\tunobserved_task_handle\t" in line for line in lines))
        self.assertTrue(any("pending" in line for line in lines))

    def test_async_helper_ignores_observed_task_handles(self) -> None:
        lines = run_helper(
            ASYNC_HELPER,
            {
                "clean.cs": """
                using System.Threading.Tasks;

                class Demo {
                    async Task<int> AwaitedAsync() {
                        var pending = Task.Run(() => 42);
                        return await pending;
                    }

                    Task<int[]> AggregatedAsync() {
                        var first = Task.Run(() => 1);
                        var second = Task.Run(() => 2);
                        return Task.WhenAll(first, second);
                    }
                }
                """,
            },
        )
        self.assertEqual(lines, [])

    def test_async_helper_reports_reassignment_before_observation(self) -> None:
        lines = run_helper(
            ASYNC_HELPER,
            {
                "reassigned.cs": """
                using System.Threading.Tasks;

                class Demo {
                    Task<int> Run() {
                        var pending = Task.Run(() => 42);
                        pending = Task.FromResult(5);
                        return pending;
                    }
                }
                """,
            },
        )
        self.assertTrue(any("\tunobserved_task_handle\t" in line for line in lines))


@unittest.skipUnless(os.environ.get("UBS_CSHARP_SEMANTICS_PUBLIC") == "1",
                     "set UBS_CSHARP_SEMANTICS_PUBLIC=1 after verified module/helper pins")
class CSharpSemanticPublicTests(unittest.TestCase):
    """The actual module and runner preserve the same source sites and exits."""

    def execute(self, source, category, mode, expected, *, extra=(), partial=False):
        artifacts = REPO_ROOT / "test-suite" / "artifacts" / "csharp-semantics"
        artifacts.mkdir(parents=True, exist_ok=True)
        folder = Path(tempfile.mkdtemp(prefix="public-", dir=artifacts))
        target = folder / "Case.cs"
        target.write_text(source, encoding="utf-8")
        skipped = ",".join(str(number) for number in range(1, 25) if number != category)
        format_ = mode.split("-")[-1]
        if mode.startswith("module-"):
            command = [str(REPO_ROOT / "modules" / "ubs-csharp.sh")]
        else:
            command = [str(REPO_ROOT / "ubs"), "--no-config", "--only=csharp"]
        command += ["--ci", "--no-dotnet", "--fail-on-warning", "--skip=" + skipped,
                    "--format=" + format_, *extra, str(target)]
        env = dict(os.environ, UBS_NO_AUTO_UPDATE="1", UBS_ENABLE_AUTO_UPDATE="0",
                   ENABLE_UV_TOOLS="0", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1",
                   UBS_NO_CACHE="1", UBS_CACHE_DIR=str(folder / "cache"), TMPDIR=str(folder))
        started = time.monotonic()
        result = subprocess.run(command, cwd=folder, env=env, text=True,
                                capture_output=True, check=False, timeout=120)
        elapsed = time.monotonic() - started
        (folder / "stdout.json").write_text(result.stdout, encoding="utf-8")
        (folder / "stderr.log").write_text(result.stderr, encoding="utf-8")
        (folder / "receipt.json").write_text(json.dumps({
            "command": command, "exit": result.returncode, "elapsed_seconds": elapsed,
            "python": sys.version, "ast_grep": shutil.which("ast-grep"),
            "input_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "sources": {name: hashlib.sha256((REPO_ROOT / name).read_bytes()).hexdigest()
                        for name in ("ubs", "modules/ubs-csharp.sh", "modules/helpers/ubs_core/csharp_rules.py",
                                     "modules/helpers/ubs_core/analyzers/narrowing_csharp.py")},
        }, indent=2), encoding="utf-8")
        print(f"[csharp-semantics:{folder.name}] {mode} exit={result.returncode} {elapsed:.3f}s", flush=True)
        details = f"{command!r}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        self.assertEqual(result.returncode, 2 if partial else int(bool(expected)), details)
        if partial:
            self.assertIn("incomplete", result.stderr, details)
        try:
            report = json.loads(result.stdout)
        except ValueError as exc:
            self.fail(f"invalid {format_}: {exc}\n{details}")
        actual = []
        if format_ == "sarif":
            successful = []
            for run in report["runs"]:
                successful.extend(invocation["executionSuccessful"] for invocation in run.get("invocations", []))
                for finding in run.get("results", []):
                    location = finding["locations"][0]["physicalLocation"]
                    self.assertEqual(Path(location["artifactLocation"]["uri"]).name, "Case.cs", details)
                    self.assertEqual(finding["level"], "warning", details)
                    actual.append((finding["ruleId"], location["region"]["startLine"],
                                   location["region"]["startColumn"]))
            self.assertTrue(any(not value for value in successful) if partial else all(successful), details)
        else:
            self.assertEqual(report["status"], "partial" if partial else "ok", details)
            counts = report if mode.startswith("module-") else report["totals"]
            self.assertEqual((counts["critical"], counts["warning"], counts["info"], counts["files"]),
                             (0, len(expected), 0, 1), details)
            records = report.get("findings")
            if records is None and not mode.startswith("module-"):
                # Empty meta reports retain the strict module evidence but
                # need not add a duplicate flattened findings array.
                self.assertEqual(len(report["scanners"]), 1, details)
                records = report["scanners"][0]["findings"]
            self.assertIsInstance(records, list, details)
            for finding in records:
                self.assertEqual(finding["severity"], "warning", details)
                self.assertEqual(Path(finding.get("path", finding.get("file"))).name, "Case.cs", details)
                actual.append((finding.get("rule", finding.get("rule_id")), finding["line"], finding["col"]))
        self.assertEqual(sorted(actual), sorted(expected), details)

    def test_reported_guards_and_rethrows_in_json_and_sarif(self):
        cases = ((GUARD_REPRO, 1, "expect-negative", "csharp.narrowing.negative_guard", "p.Value"),
                 (RETHROW_REPRO, 17, "expect-rethrow", "cs-rethrow-ex", "throw "))
        for source, category, marker, rule, expression in cases:
            expected = [(rule, number, line.index(expression) + 1)
                        for number, line in enumerate(source.splitlines(), 1) if marker in line]
            for mode in ("module-json", "module-sarif", "json", "sarif"):
                with self.subTest(category=category, mode=mode):
                    self.execute(source, category, mode, expected)

    def test_safe_controls_and_exact_suppression(self):
        safe_guards = 'class C { decimal Run(decimal? p) { if(p == null) Log(); return p.HasValue ? p.Value : 0; } }'
        safe_throw = 'class C { void Run() { try { throw new InvalidOperationException(); } catch(Exception ex) { throw new InvalidOperationException("wrap", ex); } } }'
        suppressed = GUARD_REPRO.replace('// expect-negative', '// ubs:ignore[csharp.narrowing.negative_guard]')
        for source, category in ((safe_guards, 1), (safe_throw, 17), (suppressed, 1)):
            for mode in ("module-json", "json", "sarif"):
                with self.subTest(category=category, mode=mode, source=source):
                    self.execute(source, category, mode, [])

    def test_callable_scope_findings_and_unsupported_scope_envelopes(self):
        expected = []
        for number, line in enumerate(GUARD_SCOPE_REPRO.splitlines(), 1):
            name = "value" if "expect-value" in line else "p" if "expect-negative" in line else None
            if name:
                expected.append(("csharp.narrowing.negative_guard", number, line.index(name + ".Length") + 1))
        for mode in ("module-json", "module-sarif", "json", "sarif"):
            with self.subTest(mode=mode, selected="supported"):
                self.execute(GUARD_SCOPE_REPRO, 1, mode, expected)
            for source in UNSUPPORTED_GUARD_SCOPES:
                with self.subTest(mode=mode, selected=source):
                    self.execute(source, 1, mode, [], partial=True)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
