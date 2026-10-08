"""Independent native Kotlin semantic oracle for mj1j.13 / mj1j.14.

The cases pin actual null assertions, cancellation handlers, blocking calls and
job acquisitions. Safe examples preserve Kotlin's value and ownership semantics;
they do not excuse a finding merely because an API or variable has a safe name.
Run UBS_KOTLIN_NATIVE_E2E=1 to include real module/meta-runner JSON/SARIF probes.
Artifacts, including source identities and complete subprocess logs, are retained.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
HELPERS = ROOT / "modules/helpers"
sys.path.insert(0, str(HELPERS))
from ubs_core import kotlin_scan

CANCELLATION = "kotlin.coroutine.swallowed-cancellation"
BLOCKING = "kotlin.coroutine.blocking-call"
JOB = "kotlin.coroutine.unowned-job"
NEGATIVE = "kotlin.narrowing.negative_guard"
POSITIVE = "kotlin.narrowing.positive_guard"
SAFECALL = "kotlin.narrowing.safecall_guard"
CAST = "kotlin.narrowing.smart_cast"
ELVIS = "kotlin.narrowing.elvis_force"
NULLABLE = "kotlin.narrowing.nullable_value"
PREFIXES = ("kotlin.coroutine.", "kotlin.narrowing.")


@dataclass(frozen=True)
class Case:
    name: str
    code: str
    rule: str = ""

    @property
    def source(self):
        return textwrap.dedent(self.code).strip("\n") + "\n"

    @property
    def expected(self):
        # The marker selects the independently identified operation, not text
        # discovered by the analyzer. Cases with no marker must remain clean.
        return sorted((self.rule, number) for number, line in enumerate(self.source.splitlines(), 1)
                      if "// expect-finding" in line)


NULL_CASES = (
    Case("null_guard_fallthrough", '''
        fun f(value: String?) {
            if (value == null) { println("missing") }
            println(value!!.length) // expect-finding
        }''', NEGATIVE),
    Case("null_guard_return", '''
        fun f(value: String?) {
            if (value == null) { return }
            println(value!!.length)
        }'''),
    Case("null_guard_conditional_return", '''
        fun f(value: String?, stop: Boolean) {
            if (value == null) { if (stop) return }
            println(value!!.length) // expect-finding
        }''', NEGATIVE),
    Case("null_guard_nested_function_return_is_not_exit", '''
        fun f(value: String?) {
            if (value == null) { fun stop() { return }; println("missing") }
            println(value!!.length) // expect-finding
        }''', NEGATIVE),
    Case("null_guard_branch_assigns_nonnull_fallback", '''
        fun f(input: String?) {
            var value = input
            if (value == null) { value = "fallback" }
            println(value!!.length)
        }'''),
    Case("null_guard_branch_rethrows_on_all_paths", '''
        fun f(value: String?, stop: Boolean) {
            if (value == null) {
                if (stop) return else throw IllegalArgumentException("missing")
            }
            println(value!!.length)
        }'''),
    Case("positive_guard_returns_nonnull_branch", '''
        fun f(value: String?) {
            if (value != null) { return }
            println(value!!.length) // expect-finding
        }''', POSITIVE),
    Case("positive_guard_dominates_assertion", '''
        fun f(value: String?) {
            if (value != null) { println(value!!.length) }
        }'''),
    Case("positive_guard_alternate_returns", '''
        fun f(value: String?) {
            if (value != null) { println("present") } else { return }
            println(value!!.length)
        }'''),
    Case("safe_call_false_branch_can_be_null", '''
        fun f(value: String?) {
            if (value?.isEmpty() == true) { return }
            println(value!!.length) // expect-finding
        }''', SAFECALL),
    Case("safe_call_true_branch_proves_receiver", '''
        fun f(value: String?) {
            if (value?.isEmpty() == true) { println(value!!.length) }
        }'''),
    Case("safe_cast_nullable_result", '''
        fun f(raw: Any?) {
            val value = raw as? String
            println(value!!.length) // expect-finding
        }''', CAST),
    Case("safe_cast_elvis_return", '''
        fun f(raw: Any?) {
            val value = raw as? String ?: return
            println(value!!.length)
        }'''),
    Case("safe_cast_elvis_literal", '''
        fun f(raw: Any?) {
            val value = raw as? String ?: "fallback"
            println(value!!.length)
        }'''),
    Case("elvis_return_proves_nonnull", '''
        fun f(raw: String?) {
            val value = raw ?: return
            println(value!!.length)
        }'''),
    Case("elvis_literal_proves_nonnull", '''
        fun f(raw: String?) {
            val value = raw ?: "fallback"
            println(value!!.length)
        }'''),
    Case("elvis_unit_is_nonnull", '''
        fun f(raw: String?) {
            val value = raw ?: println("missing")
            println(value!!.hashCode())
        }'''),
    Case("elvis_nullable_alternative", '''
        fun f(raw: String?, backup: String?) {
            val value = raw ?: backup
            println(value!!.length) // expect-finding
        }''', ELVIS),
    Case("guard_in_different_function_does_not_bind", '''
        fun inspect(value: String?) {
            if (value == null) { println("missing") }
        }
        fun display(value: String) {
            println(value!!.length)
        }'''),
    Case("cast_in_different_function_does_not_bind", '''
        fun inspect(raw: Any?) { val value = raw as? String }
        fun display(value: String) { println(value!!.length) }
        '''),
    Case("nested_scope_shadowing_is_independent", '''
        fun f(value: String?) {
            if (value == null) {
                val value = "fallback"
                println(value!!.length)
            }
        }'''),
    Case("lexical_null_decoys", '''
        fun f() {
            val example = "if (value == null) { log() }; println(value!!.length)"
            // val value = raw as? String; println(value!!.length)
            /* if (value == null) { log() }; println(value!!.length) */
            println(example)
        }'''),
    Case("string_interpolation_executes_null_assertion", '''
        fun f(value: String?) {
            if (value == null) { println("missing") }
            println("length = ${value!!.length}") // expect-finding
        }''', NEGATIVE),
    Case("raw_string_interpolation_executes_null_assertion", '''
        fun f(value: String?) {
            if (value == null) { println("missing") }
            println("""length = ${value!!.length}""") // expect-finding
        }''', NEGATIVE),
    Case("interpolated_nested_quotes_are_expressions", '''
        fun f(raw: Any?) {
            val value = raw as? MutableMap<String, String>
            println("level = ${value!!.getValue("level")}") // expect-finding
        }''', CAST),
    Case("explicit_null_literal_origin", '''
        fun f() {
            val value: String? = null
            println(value!!.length) // expect-finding
        }''', NULLABLE),
    Case("nonnull_literal_with_nullable_annotation", '''
        fun f() {
            val value: String? = "fixed"
            println(value!!.length)
        }'''),
    Case("try_mutation_reaches_exception_handler", '''
        fun f() {
            var value: String? = "fixed"
            try { value = null; throw IllegalArgumentException("stop") }
            catch (problem: Exception) {
                println(value!!.length) // expect-finding
            }
        }''', NULLABLE),
    Case("catch_parameter_shadows_nullable_binding", '''
        fun f() {
            val value: String? = null
            try { throw IllegalArgumentException("stop") }
            catch (value: Exception) { println(value!!.message) }
        }'''),
    Case("short_circuit_nonnull_branch_protects_assertion", '''
        fun f(value: String?) {
            println(value != null && value!! == "")
        }'''),
    Case("short_circuit_null_branch_exposes_assertion", '''
        fun f(value: String?) {
            println(value == null && value!! == "") // expect-finding
        }''', NEGATIVE),
)

COROUTINE_CASES = (
    Case("cancellation_explicit_swallowed", '''
        import kotlinx.coroutines.CancellationException
        import kotlinx.coroutines.delay
        suspend fun poll() {
            try { delay(1) }
            catch (cancelled: CancellationException) { println(cancelled.message) } // expect-finding
        }''', CANCELLATION),
    Case("cancellation_import_alias_swallowed", '''
        import kotlinx.coroutines.CancellationException as StopSignal
        import kotlinx.coroutines.delay
        suspend fun poll() {
            try { delay(1) }
            catch (cancelled: StopSignal) { println(cancelled.message) } // expect-finding
        }''', CANCELLATION),
    Case("cancellation_rethrown", '''
        import kotlinx.coroutines.CancellationException
        import kotlinx.coroutines.delay
        suspend fun poll() {
            try { delay(1) }
            catch (cancelled: CancellationException) { throw cancelled }
        }'''),
    Case("cancellation_alias_rethrown", '''
        import kotlinx.coroutines.CancellationException
        import kotlinx.coroutines.delay
        suspend fun poll() {
            try { delay(1) }
            catch (cancelled: CancellationException) { val original = cancelled; throw original }
        }'''),
    Case("cancellation_only_one_path_rethrows", '''
        import kotlinx.coroutines.CancellationException
        import kotlinx.coroutines.delay
        suspend fun poll(stop: Boolean) {
            try { delay(1) }
            catch (cancelled: CancellationException) { if (stop) throw cancelled } // expect-finding
        }''', CANCELLATION),
    Case("cancellation_both_branches_rethrow", '''
        import kotlinx.coroutines.CancellationException
        import kotlinx.coroutines.delay
        suspend fun poll(stop: Boolean) {
            try { delay(1) }
            catch (cancelled: CancellationException) { if (stop) throw cancelled else throw cancelled }
        }'''),
    Case("cancellation_nested_function_throw_is_not_rethrow", '''
        import kotlinx.coroutines.CancellationException
        import kotlinx.coroutines.delay
        suspend fun poll() {
            try { delay(1) }
            catch (cancelled: CancellationException) { // expect-finding
                fun rethrowLater(): Nothing { throw cancelled }
                println("continued")
            }
        }''', CANCELLATION),
    Case("cancellation_replaced_with_unrelated_exception", '''
        import kotlinx.coroutines.CancellationException
        import kotlinx.coroutines.delay
        suspend fun poll() {
            try { delay(1) }
            catch (cancelled: CancellationException) { throw IllegalStateException("failed") } // expect-finding
        }''', CANCELLATION),
    Case("cancellation_unrelated_class", '''
        class CancellationException : Exception()
        suspend fun poll() {
            try { throw CancellationException() }
            catch (cancelled: CancellationException) { println(cancelled.message) }
        }'''),
    Case("cancellation_ordinary_sync_handler", '''
        import kotlinx.coroutines.CancellationException
        fun convert() {
            try { throw CancellationException("cancelled") }
            catch (cancelled: CancellationException) { println(cancelled.message) }
        }'''),
    Case("cancellation_generic_catch_is_not_blanket_alert", '''
        suspend fun convert() {
            try { Integer.parseInt("123") }
            catch (problem: Exception) { println(problem.message) }
        }'''),
    Case("blocking_sleep_in_suspend", '''
        suspend fun poll() {
            Thread.sleep(25) // expect-finding
        }''', BLOCKING),
    Case("blocking_sleep_fully_qualified", '''
        suspend fun poll() {
            java.lang.Thread.sleep(25) // expect-finding
        }''', BLOCKING),
    Case("blocking_sleep_in_structured_launch", '''
        import kotlinx.coroutines.coroutineScope
        import kotlinx.coroutines.launch
        suspend fun poll() = coroutineScope {
            launch {
                Thread.sleep(25) // expect-finding
            }
        }''', BLOCKING),
    Case("blocking_sleep_on_io_dispatcher", '''
        import kotlinx.coroutines.Dispatchers
        import kotlinx.coroutines.withContext
        suspend fun poll() {
            withContext(Dispatchers.IO) { Thread.sleep(25) }
        }'''),
    Case("blocking_sleep_io_import_alias", '''
        import kotlinx.coroutines.Dispatchers as WorkerDispatchers
        import kotlinx.coroutines.withContext as switchContext
        suspend fun poll() {
            switchContext(WorkerDispatchers.IO) { Thread.sleep(25) }
        }'''),
    Case("blocking_sleep_default_dispatcher", '''
        import kotlinx.coroutines.Dispatchers
        import kotlinx.coroutines.withContext
        suspend fun poll() {
            withContext(Dispatchers.Default) { Thread.sleep(25) } // expect-finding
        }''', BLOCKING),
    Case("blocking_sleep_sync_function", '''
        fun poll() { Thread.sleep(25) }
        '''),
    Case("blocking_sleep_shadowed_thread", '''
        object Thread { fun sleep(value: Int) { println(value) } }
        suspend fun poll() { Thread.sleep(25) }
        '''),
    Case("blocking_sleep_shadowed_parameter", '''
        class Worker { fun sleep(value: Int) { println(value) } }
        suspend fun poll(Thread: Worker) { Thread.sleep(25) }
        '''),
    Case("job_global_launch_discarded", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        fun start() {
            GlobalScope.launch { println("work") } // expect-finding
        }''', JOB),
    Case("job_global_launch_assigned_but_unobserved", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        fun start() {
            val job = GlobalScope.launch { println("work") } // expect-finding
            println("started")
        }''', JOB),
    Case("job_global_launch_to_string_does_not_observe", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        fun start() {
            GlobalScope.launch { println("work") }.toString() // expect-finding
        }''', JOB),
    Case("job_println_does_not_take_ownership", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        fun start() {
            val job = GlobalScope.launch { println("work") } // expect-finding
            println(job)
        }''', JOB),
    Case("job_direct_println_argument_is_not_transferred", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        fun start() {
            println(GlobalScope.launch { println("work") }) // expect-finding
        }''', JOB),
    Case("job_builtin_null_checks_do_not_take_ownership", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        fun start() {
            val checked = GlobalScope.launch { println("work") } // expect-finding
            checkNotNull(checked)
            val required = GlobalScope.launch { println("work") } // expect-finding
            requireNotNull(required)
        }''', JOB),
    Case("job_explicit_handoff_transfers_ownership", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.Job
        import kotlinx.coroutines.launch
        private var owned: Job? = null
        fun handoff(job: Job) { owned = job }
        fun start() {
            val job = GlobalScope.launch { println("work") }
            handoff(job)
        }'''),
    Case("job_local_println_owner_shadows_builtin", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.Job
        import kotlinx.coroutines.launch
        private var owned: Job? = null
        fun println(job: Job) { owned = job }
        fun start() {
            val job = GlobalScope.launch { }
            println(job)
        }'''),
    Case("job_parenthesized_alias_discarded", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        fun start() {
            val job = GlobalScope.launch { println("work") } // expect-finding
            val alias = (job)
            println("started")
        }''', JOB),
    Case("job_parenthesized_alias_joined", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        suspend fun start() {
            val job = GlobalScope.launch { println("work") }
            val alias = (job)
            alias.join()
        }'''),
    Case("job_null_check_alias_discarded", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        fun start() {
            val job = GlobalScope.launch { println("work") } // expect-finding
            val checked = checkNotNull(job)
            println("started")
        }''', JOB),
    Case("job_null_check_alias_joined", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        suspend fun start() {
            val job = GlobalScope.launch { println("work") }
            val checked = requireNotNull(job)
            checked.join()
        }'''),
    Case("job_null_check_result_returned", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.Job
        import kotlinx.coroutines.launch
        fun start(): Job {
            val job = GlobalScope.launch { println("work") }
            return checkNotNull(job)
        }'''),
    Case("job_null_check_result_stored_with_owner", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.Job
        import kotlinx.coroutines.launch
        object Owner { var job: Job? = null }
        fun start() {
            val job = GlobalScope.launch { println("work") }
            Owner.job = requireNotNull(job)
        }'''),
    Case("job_global_launch_returned", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.Job
        import kotlinx.coroutines.launch
        fun start(): Job { return GlobalScope.launch { println("work") } }
        '''),
    Case("job_global_launch_expression_return", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        fun start() = GlobalScope.launch { println("work") }
        '''),
    Case("job_global_launch_joined", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        suspend fun start() {
            val job = GlobalScope.launch { println("work") }
            job.join()
        }'''),
    Case("job_global_launch_alias_joined", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        suspend fun start() {
            val job = GlobalScope.launch { println("work") }
            val owned = job
            owned.join()
        }'''),
    Case("job_global_launch_cancelled_and_joined", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.cancelAndJoin
        import kotlinx.coroutines.launch
        suspend fun start() {
            val job = GlobalScope.launch { println("work") }
            job.cancelAndJoin()
        }'''),
    Case("job_other_handle_join_does_not_discharge", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.Job
        import kotlinx.coroutines.launch
        suspend fun start(other: Job) {
            val job = GlobalScope.launch { println("work") } // expect-finding
            other.join()
        }''', JOB),
    Case("job_join_on_only_one_path", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        suspend fun start(wait: Boolean) {
            val job = GlobalScope.launch { println("work") } // expect-finding
            if (wait) { job.join() }
        }''', JOB),
    Case("job_join_on_both_paths", '''
        import kotlinx.coroutines.GlobalScope
        import kotlinx.coroutines.launch
        suspend fun start(wait: Boolean) {
            val job = GlobalScope.launch { println("work") }
            if (wait) { job.join() } else { job.cancel(); job.join() }
        }'''),
    Case("job_selected_parent_scope_owns_launch", '''
        import kotlinx.coroutines.CoroutineScope
        import kotlinx.coroutines.launch
        fun start(scope: CoroutineScope) { scope.launch { println("work") } }
        '''),
    Case("job_structured_scope_owns_launch", '''
        import kotlinx.coroutines.coroutineScope
        import kotlinx.coroutines.launch
        suspend fun start() = coroutineScope { launch { println("work") } }
        '''),
    Case("job_shadowed_globalscope", '''
        object GlobalScope { fun launch(block: () -> Unit) { block() } }
        fun start() { GlobalScope.launch { println("work") } }
        '''),
    Case("coroutine_lexical_decoys", '''
        val example = "suspend fun f() { Thread.sleep(1) }"
        // import kotlinx.coroutines.GlobalScope
        // GlobalScope.launch { Thread.sleep(1) }
        /* suspend fun f() { catch (e: CancellationException) { println(e) } } */
        '''),
)
CASES = NULL_CASES + COROUTINE_CASES
BY_NAME = {case.name: case for case in CASES}


class LoggedKotlinCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = ROOT / "test-suite/artifacts/kotlin-native-semantics" / (cls.__name__ + "-" + uuid.uuid4().hex[:12])
        cls.artifacts.mkdir(parents=True)
        paths = (HELPERS / "ubs_core/kotlin_scan.py", HELPERS / "ubs_core/analyzers/narrowing_kotlin.py",
                 HELPERS / "ubs_core/analyzers/coroutines_kotlin.py")
        identity = {"python": sys.version, "executable": sys.executable,
                    "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=30).strip(),
                    "sources": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in paths if path.is_file()}}
        (cls.artifacts / "source-identity.json").write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
        print(f"[{cls.__name__}] artifacts: {cls.artifacts}", flush=True)

    def setUp(self):
        self.started = time.monotonic()
        result = self._outcome.result
        self.failures_before = len(result.failures) + len(result.errors)
        print(f"[{self.id()}] RUN", flush=True)

    def tearDown(self):
        result = self._outcome.result
        failed = len(result.failures) + len(result.errors) > self.failures_before
        print(f"[{self.id()}] {'FAIL' if failed else 'PASS'} ({time.monotonic() - self.started:.3f}s)", flush=True)

    def fixture(self, case, suffix=""):
        directory = self.artifacts / (case.name + suffix)
        directory.mkdir(exist_ok=True)
        source = directory / "Input.kt"
        source.write_text(case.source, encoding="utf-8")
        return directory, source

    def assert_records(self, case, records):
        actual = sorted((record["rule"], record["line"]) for record in records
                        if record["rule"].startswith(PREFIXES))
        self.assertEqual(actual, case.expected, (case.source, records))
        for record in records:
            if record["rule"].startswith(PREFIXES):
                self.assertEqual(record["severity"], "warning", record)
                self.assertGreater(record["col"], 0, record)
                self.assertEqual(Path(record["path"]).name, "Input.kt", record)


class KotlinNativeAnalyzerTests(LoggedKotlinCase):
    def check_cases(self, cases):
        for case in cases:
            with self.subTest(case=case.name):
                directory, source = self.fixture(case)
                sink, stdout, stderr = io.StringIO(), io.StringIO(), io.StringIO()
                started = time.monotonic()
                status, error, records = "FAIL", None, []
                print(f"[{case.name}] RUN", flush=True)
                try:
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        kotlin_scan.scan_analyzers([source], sink, set())
                    records = [json.loads(line) for line in sink.getvalue().splitlines() if line]
                    self.assert_records(case, records)
                    status = "PASS"
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                    raise
                finally:
                    (directory / "stdout.log").write_text(stdout.getvalue(), encoding="utf-8")
                    (directory / "stderr.log").write_text(stderr.getvalue(), encoding="utf-8")
                    (directory / "result.json").write_text(json.dumps({
                        "case": case.name, "expected": case.expected, "status": status,
                        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                        "elapsed": time.monotonic() - started, "error": error, "findings": records,
                    }, indent=2) + "\n", encoding="utf-8")
                    print(f"[{case.name}] {status} ({time.monotonic() - started:.3f}s)", flush=True)

    def test_null_binding_and_control_flow(self):
        self.check_cases(NULL_CASES)

    def test_coroutine_api_identity_context_and_ownership(self):
        self.check_cases(COROUTINE_CASES)


@unittest.skipUnless(os.environ.get("UBS_KOTLIN_NATIVE_E2E") == "1", "set UBS_KOTLIN_NATIVE_E2E=1 for actual CLI scans")
class KotlinNativeCliTests(LoggedKotlinCase):
    @staticmethod
    def meta_records(payload):
        return [record for scanner in payload.get("scanners", []) for record in scanner.get("findings", [])]

    def scan(self, case, *, fmt="json", meta=False, flags=(), env_updates=None, suffix="", fail_on_warning=True):
        directory, source = self.fixture(case, suffix)
        cache = directory / "cache"
        temporary = directory / "temporary"
        temporary.mkdir(exist_ok=True)
        command = ([str(ROOT / "ubs"), "--only=kotlin"] if meta else ["bash", str(ROOT / "modules/ubs-kotlin.sh")])
        command += ["--ci", "--format=" + fmt]
        if fail_on_warning:
            command.append("--fail-on-warning")
        command += [*flags, str(source)]
        env = dict(os.environ, UBS_NO_AUTO_UPDATE="1", UBS_NO_CACHE="1", PYTHONDONTWRITEBYTECODE="1",
                   UBS_CACHE_DIR=str(cache), TMPDIR=str(temporary), XDG_CACHE_HOME=str(cache), NO_COLOR="1")
        if env_updates:
            env.update(env_updates)
        started = time.monotonic()
        print(f"[{case.name}:{'meta' if meta else 'module'}:{fmt}] RUN", flush=True)
        result = subprocess.run(command, cwd=directory, env=env, text=True, capture_output=True, timeout=120)  # ubs:ignore[py.security.command-injection] - trusted repo runner and fixed test fixtures form argv; subprocess uses shell=False.
        name = ("meta" if meta else "module") + "-" + fmt
        run_directory = directory / "runs" / (name + "-" + uuid.uuid4().hex[:8])
        run_directory.mkdir(parents=True)
        (run_directory / "Input.kt").write_text(case.source, encoding="utf-8")
        (run_directory / "stdout.log").write_text(result.stdout, encoding="utf-8")
        (run_directory / "stderr.log").write_text(result.stderr, encoding="utf-8")
        (run_directory / "command.json").write_text(json.dumps({
            "command": command, "cwd": str(directory), "elapsed": time.monotonic() - started,
            "returncode": result.returncode, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "environment": {key: env[key] for key in ("UBS_NO_CACHE", "UBS_CACHE_DIR", "TMPDIR", "UBS_NO_AUTO_UPDATE")},
        }, indent=2) + "\n", encoding="utf-8")
        try:
            payload = json.loads(result.stdout)
        except ValueError:
            self.fail((command, result.returncode, result.stdout, result.stderr))
        return result, payload

    def test_ordinary_module_json_and_sarif_agree(self):
        names = ("cancellation_explicit_swallowed", "blocking_sleep_in_suspend", "job_global_launch_discarded",
                 "null_guard_conditional_return", "elvis_return_proves_nonnull", "blocking_sleep_on_io_dispatcher")
        for name in names:
            case = BY_NAME[name]
            for fmt in ("json", "sarif"):
                with self.subTest(case=name, format=fmt):
                    result, payload = self.scan(case, fmt=fmt)
                    self.assertEqual(result.returncode, 1 if case.expected else 0, (result.stdout, result.stderr))
                    if fmt == "json":
                        self.assertEqual(payload["status"], "ok", payload)
                        self.assertEqual(payload["files"], 1, payload)
                        self.assert_records(case, payload["findings"])
                        self.assertEqual(payload["critical"], 0, payload)
                        self.assertEqual(payload["warning"], len(case.expected), payload)
                    else:
                        actual = sorted((record["ruleId"], record["locations"][0]["physicalLocation"]["region"]["startLine"])
                                        for run in payload["runs"] for record in run["results"]
                                        if record["ruleId"].startswith(PREFIXES))
                        self.assertEqual(actual, case.expected, payload)

    def test_ordinary_meta_runner_counts_active_rules(self):
        for name in ("cancellation_explicit_swallowed", "blocking_sleep_in_suspend", "job_global_launch_discarded",
                     "null_guard_conditional_return", "elvis_literal_proves_nonnull"):
            case = BY_NAME[name]
            with self.subTest(case=name):
                result, payload = self.scan(case, meta=True)
                self.assertEqual(result.returncode, 1 if case.expected else 0, (result.stdout, result.stderr))
                self.assert_records(case, self.meta_records(payload))
                self.assertEqual(payload["totals"]["warning"], len(case.expected), payload)
                self.assertEqual(payload["totals"]["critical"], 0, payload)

    def test_category_selection_and_scoped_suppression(self):
        case = BY_NAME["blocking_sleep_in_suspend"]
        result, payload = self.scan(case, flags=("--skip=3",), suffix="-skip")
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(payload["findings"], [], payload)
        suppressed = Case("blocking_suppressed", case.source.replace("// expect-finding", "// ubs:ignore[" + BLOCKING + "]"))
        result, payload = self.scan(suppressed, meta=True)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assert_records(suppressed, self.meta_records(payload))
        unrelated = Case("blocking_wrong_suppression", case.source.replace("// expect-finding", "// ubs:ignore[" + JOB + "] // expect-finding"), BLOCKING)
        result, payload = self.scan(unrelated, meta=True)
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
        self.assert_records(unrelated, self.meta_records(payload))

    def test_profiles_keep_findings_and_apply_their_exit_policy(self):
        case = BY_NAME["blocking_sleep_in_suspend"]
        for profile, expected_exit in ((None, 0), ("strict", 1), ("loose", 0)):
            with self.subTest(profile=profile):
                flags = ("--profile=" + profile,) if profile else ()
                result, payload = self.scan(case, meta=True, flags=flags, fail_on_warning=False,
                                            suffix="-profile-" + (profile or "default"))
                self.assertEqual(result.returncode, expected_exit, (result.stdout, result.stderr))
                self.assert_records(case, self.meta_records(payload))

    def test_malformed_source_and_budget_exhaustion_are_explicit(self):
        malformed = Case("malformed_block", "suspend fun poll() {\n    Thread.sleep(25)\n")
        cases = ((malformed, {}), (BY_NAME["blocking_sleep_in_suspend"], {"UBS_KOTLIN_MAX_TOKENS": "5"}))
        for case, env in cases:
            with self.subTest(case=case.name, environment=env):
                result, payload = self.scan(case, env_updates=env, suffix="-incomplete")
                self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
                self.assertEqual(payload["status"], "partial", payload)
                self.assertEqual(payload["module_error"], "ANALYZER_ERROR", payload)
                self.assertIn("incomplete", result.stderr.lower(), result.stderr)

    def test_cache_replays_and_invalidates_changed_source_and_policy(self):
        unsafe = BY_NAME["blocking_sleep_in_suspend"]
        cache_root = self.artifacts / "shared-cache"
        env = {"UBS_NO_CACHE": "0", "UBS_CACHE_DIR": str(cache_root)}
        for iteration in range(2):
            result, payload = self.scan(unsafe, env_updates=env, suffix="-cached")
            self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
            self.assert_records(unsafe, payload["findings"])
            if iteration:
                self.assertEqual(payload["extras"]["profile"]["cache_hits"], 1, payload)
        safe = Case(unsafe.name, "fun poll() { Thread.sleep(25) }")
        result, payload = self.scan(safe, env_updates=env, suffix="-cached")
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assert_records(safe, payload["findings"])
        self.assertEqual(payload["extras"]["profile"]["cache_misses"], 1, payload)
        result, payload = self.scan(unsafe, flags=("--skip=3",), env_updates=env, suffix="-cached")
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(payload["findings"], [], payload)
        result, payload = self.scan(unsafe, env_updates=env, suffix="-cached")
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
        self.assert_records(unsafe, payload["findings"])

    def test_nul_file_selection_excludes_an_unselected_unsafe_file(self):
        safe = BY_NAME["elvis_literal_proves_nonnull"]
        directory, selected = self.fixture(safe, "-selection")
        unselected = directory / "Unselected.kt"
        unselected.write_text(BY_NAME["blocking_sleep_in_suspend"].source, encoding="utf-8")
        selection = directory / "selected-files.nul"
        selection.write_bytes(os.fsencode(selected) + b"\0")
        command = ["bash", str(ROOT / "modules/ubs-kotlin.sh"), "--ci", "--format=json", "--fail-on-warning",
                   "--files-from=" + str(selection), str(directory)]
        temporary = directory / "temporary"
        temporary.mkdir(exist_ok=True)
        env = dict(os.environ, UBS_NO_AUTO_UPDATE="1", UBS_NO_CACHE="1", PYTHONDONTWRITEBYTECODE="1",
                   TMPDIR=str(temporary), XDG_CACHE_HOME=str(directory / "cache"))
        started = time.monotonic()
        result = subprocess.run(command, cwd=directory, env=env, text=True, capture_output=True, timeout=120)
        (directory / "selection.stdout.log").write_text(result.stdout, encoding="utf-8")
        (directory / "selection.stderr.log").write_text(result.stderr, encoding="utf-8")
        (directory / "selection.command.json").write_text(json.dumps({"command": command,
            "elapsed": time.monotonic() - started, "returncode": result.returncode}, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(("Invalid scanner JSON", str(exc), command, result.stdout, result.stderr))
        self.assertEqual(payload["files"], 1, payload)
        self.assertEqual(payload["findings"], [], payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
