"""Independent Ruby resource identity controls and real public CLI probes.

The expected obligations follow the Ruby APIs, before choosing an analysis:
https://docs.ruby-lang.org/en/3.4/Thread.html
https://docs.ruby-lang.org/en/3.4/IO.html#method-c-open
https://docs.ruby-lang.org/en/3.4/syntax/exceptions_rdoc.html

Thread#join without a deadline and Thread#value observe that receiver. Array
iteration invokes a block for each member; Array#join merely formats strings.
Assignments copy references, method parameters have their own bindings, and
ensure runs even when the protected body returns or raises. These fixtures
deliberately pair each safe operation with an unsafe ownership near miss.
"""
from __future__ import annotations

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
sys.path.insert(0, str(ROOT / "modules/helpers"))
from ubs_core.analyzers import lifecycle_ruby
from ubs_core.io import line_col

THREAD = "ruby.lifecycle.thread_join"
FILE = "ruby.lifecycle.file_handle"
HTTP = "ruby.lifecycle.http_session"
RULES = {THREAD, FILE, HTTP}


@dataclass(frozen=True)
class Case:
    name: str
    code: str
    expected: tuple[tuple[str, int], ...]

    @property
    def source(self):
        return textwrap.dedent(self.code).strip("\n") + "\n"


CASES = (
    Case("direct_thread_leak", "worker = Thread.new { work }", ((THREAD, 1),)),
    Case("direct_thread_join", "worker = Thread.new { work }\nworker.join", ()),
    Case("thread_value_observes_result", "worker = Thread.new { work }\nworker.value", ()),
    Case("unrelated_join_does_not_observe_anonymous_thread", "Thread.new { work }\nother.join", ((THREAD, 1),)),
    Case("uncalled_method_does_not_join_outer_thread", '''
        worker = Thread.new { work }
        def cleanup(worker)
          worker.join
        end''', ((THREAD, 1),)),
    Case("sibling_method_names_are_distinct", '''
        def start_work
          worker = Thread.new { work }
          puts 'started'
        end
        def finish_work(worker)
          worker.join
        end''', ((THREAD, 2),)),
    Case("alias_observes_original_thread", "worker = Thread.new { work }\ncopy = worker\ncopy.join", ()),
    Case("reassignment_drops_original_thread", "worker = Thread.new { work }\nworker = other\nworker.join", ((THREAD, 1),)),
    Case("new_binding_does_not_discharge_old_thread", "worker = Thread.new { first }\nworker = Thread.new { second }\nworker.join", ((THREAD, 1),)),
    Case("alias_survives_thread_reassignment", "worker = Thread.new { first }\ncopy = worker\nworker = Thread.new { second }\ncopy.join\nworker.join", ()),
    Case("join_before_assignment_has_no_effect", "worker.join\nworker = Thread.new { work }", ((THREAD, 2),)),
    Case("collection_joined_with_symbol", '''
        workers = []
        10.times do |i|
          workers << Thread.new do
            work(i)
          end
        end
        workers.each(&:join)''', ()),
    Case("collection_joined_with_block", "workers = []\nworkers << Thread.new { work }\nworkers.each { |worker| worker.join }", ()),
    Case("collection_values_observed", "workers = []\nworkers << Thread.new { work }\nworkers.map(&:value)", ()),
    Case("unrelated_collection_join_is_not_proof", "workers = []\nThread.new { work }\nworkers.each(&:join)", ((THREAD, 2),)),
    Case("array_join_does_not_observe_threads", "workers = []\nworkers << Thread.new { work }\nworkers.join", ((THREAD, 2),)),
    Case("collection_reassignment_loses_members", "workers = []\nworkers << Thread.new { work }\nworkers = []\nworkers.each(&:join)", ((THREAD, 2),)),
    Case("collection_alias_retains_members", "workers = []\ncopy = workers\nworkers << Thread.new { work }\nworkers = []\ncopy.each(&:join)", ()),
    Case("late_member_is_not_already_observed", "workers = []\nworkers << Thread.new { first }\nworkers.each(&:join)\nworkers << Thread.new { second }", ((THREAD, 4),)),
    Case("iterator_parameter_shadows_outer_handle", "worker = Thread.new { work }\nothers.each { |worker| worker.join }", ((THREAD, 1),)),
    Case("conditional_join_leaves_obligation", "worker = Thread.new { work }\nworker.join if ready", ((THREAD, 1),)),
    Case("both_branches_observe_same_thread", '''
        worker = Thread.new { work }
        if ready
          worker.join
        else
          worker.value
        end''', ()),
    Case("branch_binding_is_observed_after_merge", '''
        if ready
          worker = Thread.new { first }
        else
          worker = Thread.new { second }
        end
        worker.join''', ()),
    Case("timeout_is_not_completion", "worker = Thread.new { work }\nworker.join(0.01)", ((THREAD, 1),)),
    Case("nil_timeout_waits_for_completion", "worker = Thread.new { work }\nworker.join(nil)", ()),
    Case("kill_does_not_observe_completion", "worker = Thread.new { work }\nworker.kill", ((THREAD, 1),)),
    Case("literal_join_is_not_code", "worker = Thread.new { work }\nputs 'worker.join'\n# worker.join", ((THREAD, 1),)),
    Case("file_alias_closes_original", "handle = File.open('data')\ncopy = handle\ncopy.close", ()),
    Case("file_reassignment_keeps_old_obligation", "handle = File.open('first')\nhandle = File.open('second')\nhandle.close", ((FILE, 1),)),
    Case("method_close_does_not_release_outer_file", "handle = File.open('data')\ndef cleanup(handle)\n  handle.close\nend", ((FILE, 1),)),
    Case("unrelated_file_block_does_not_own_outer_file", "handle = File.open('first')\nFile.open('second') { |handle| handle.read }", ((FILE, 1),)),
    Case("file_block_owns_its_handle", "File.open('data') { |handle| handle.read }", ()),
    Case("file_block_rebinding_does_not_close_new_handle", "File.open('first') do |handle|\n  handle = File.open('second')\nend", ((FILE, 2),)),
    Case("explicit_raise_skips_later_close", "handle = File.open('data')\nraise 'failed'\nhandle.close", ((FILE, 1),)),
    Case("ensure_closes_on_raise", "handle = File.open('data')\nbegin\n  raise 'failed'\nensure\n  handle.close\nend", ()),
    Case("conditional_ensure_does_not_prove_close", "handle = File.open('data')\nbegin\n  work\nensure\n  handle.close if ready\nend", ((FILE, 1),)),
    Case("returned_handle_transfers_ownership", "def open_data\n  handle = File.open('data')\n  return handle\nend", ()),
    Case("implicit_return_transfers_ownership", "def open_data\n  handle = File.open('data')\n  handle\nend", ()),
    Case("http_alias_finishes_original", "session = Net::HTTP.start('example.com')\ncopy = session\ncopy.finish", ()),
    Case("unrelated_http_finish_does_not_discharge_session", "Net::HTTP.start('example.com')\nother.finish", ((HTTP, 1),)),
    Case("http_block_owns_session", "Net::HTTP.start('example.com') { |session| session.get('/') }", ()),
    Case("constant_rebinding_is_not_builtin_thread", "Thread = custom_factory\nworker = Thread.new { work }", ()),
    Case("constant_rebinding_is_not_builtin_file", "File = custom_factory\nhandle = File.open('data')", ()),
    Case("thread_inline_receiver_join", "Thread.new { work }.join", ()),
    Case("thread_inline_receiver_value", "Thread.new { work }.value", ()),
    Case("string_nil_is_not_unlimited_timeout", "worker = Thread.new { work }\nworker.join('nil')", ((THREAD, 1),)),
    Case("thread_array_literal_alias", "worker = Thread.new { work }\nworkers = [worker]\nworkers.each(&:join)", ()),
    Case("collection_push_and_pop_keep_identity", "workers = []\nworker = Thread.new { work }\nworkers.push(worker)\nworkers.pop.join", ()),
    Case("collection_clear_abandons_members", "workers = []\nworkers << Thread.new { work }\nworkers.clear\nworkers.each(&:join)", ((THREAD, 2),)),
    Case("unjoined_member_remains_after_pop", "workers = []\nworkers << Thread.new { first }\nworkers << Thread.new { second }\nworkers.pop.join", ((THREAD, 2),)),
    Case("known_map_preserves_all_returned_threads", "workers = [1, 2].map { |item| Thread.new { work(item) } }\nworkers.each(&:join)", ()),
    Case("conditional_iterator_join_leaves_member", "workers = []\nworkers << Thread.new { work }\nworkers.each { |worker| worker.join if ready }", ((THREAD, 2),)),
    Case("iterator_break_does_not_observe_later_members", "workers = []\nworkers << Thread.new { first }\nworkers << Thread.new { second }\nworkers.each { |worker| worker.join; break }", ((THREAD, 3),)),
    Case("unknown_iterator_may_be_empty", "worker = Thread.new { work }\nothers.each { worker.join }", ((THREAD, 1),)),
    Case("repeated_acquisition_loses_earlier_iteration", "worker = nil\n2.times { worker = Thread.new { work } }\nworker.join", ((THREAD, 2),)),
    Case("zero_iteration_does_not_allocate_thread", "0.times { Thread.new { work } }", ()),
    Case("file_block_without_parentheses_owns_handle", "File.open 'data' do |handle|\n  handle.read\nend", ()),
    Case("symbols_are_not_factories", "puts :File.open\nputs :Thread.new", ()),
    Case("interpolation_can_allocate_a_resource", 'puts "#{File.open(\'data\')}"', ((FILE, 1),)),
    Case("heredoc_factory_decoy_does_not_allocate", "message = <<~EXAMPLE\n  worker = Thread.new { work }\nEXAMPLE\nputs message", ()),
    Case("branch_return_skips_later_close", "def read_data\n  handle = File.open('data')\n  return nil if ready\n  handle.close\nend", ((FILE, 2),)),
    Case("ensure_closes_before_method_return", "def read_data\n  handle = File.open('data')\n  begin\n    return nil\n  ensure\n    handle.close\n  end\nend", ()),
    Case("thread_do_block_still_requires_observation", "Thread.new do\n  work\nend", ((THREAD, 1),)),
    Case("repeated_file_close_is_idempotent", "handle = File.open('data')\nhandle.close\nhandle.close", ()),
    Case("repeated_thread_join_is_valid", "worker = Thread.new { work }\nworker.join\nworker.join", ()),
    Case("repeated_http_finish_is_an_error", "session = Net::HTTP.start('example.com')\nsession.finish\nsession.finish", ((HTTP, 3),)),
    Case("http_alias_cannot_finish_twice", "session = Net::HTTP.start('example.com')\ncopy = session\nsession.finish\ncopy.finish", ((HTTP, 4),)),
    Case("guarded_http_finish_is_safe", "session = Net::HTTP.start('example.com')\nsession.finish\nsession.finish if session.started?", ()),
    Case("file_closed_guard_releases_handle", "handle = File.open('data')\nhandle.close unless handle.closed?", ()),
    Case("negative_index_observes_selected_member", "workers = [Thread.new { work }]\nworkers[-1].join", ()),
    Case("three_threads_need_three_observations", "workers = []\n3.times do\n  workers << Thread.new { work }\nend\nworkers[0].join\nworkers[1].join\nputs 'done'", ((THREAD, 3),)),
    Case("three_threads_all_observed", "workers = []\n3.times do\n  workers << Thread.new { work }\nend\nworkers[0].join\nworkers[1].join\nworkers[2].join", ()),
    Case("shadowed_file_block_does_not_prove_execution", "worker = Thread.new { work }\nFile = custom_factory\nFile.open('data') { worker.join }", ((THREAD, 1),)),
    Case("non_factory_block_does_not_own_file", "File.open('data').freeze { |handle| handle.close }", ((FILE, 1),)),
    Case("array_receiver_block_observes_inline_thread", "[Thread.new { work }].each { |worker| worker.join }", ()),
    Case("double_finish_skips_later_file_close", "handle = File.open('data')\nsession = Net::HTTP.start('example.com')\nsession.finish\nsession.finish\nhandle.close", ((FILE, 1), (HTTP, 4))),
    Case("ensure_closes_file_after_double_finish", "handle = File.open('data')\nsession = Net::HTTP.start('example.com')\nbegin\n  session.finish\n  session.finish\nensure\n  handle.close\nend", ((HTTP, 5),)),
    Case("bare_marker_suppresses_its_acquisition", "worker = Thread.new { work } # ubs:ignore", ()),
    Case("scoped_marker_suppresses_matching_acquisition", "worker = Thread.new { work } # ubs:ignore[ruby.lifecycle.thread_join]", ()),
    Case("preceding_marker_suppresses_next_acquisition", "# ubs:ignore[ruby.lifecycle.thread_join]\nworker = Thread.new { work }", ()),
    Case("multiline_marker_owns_acquisition_statement", "handle = File.open(\n  'data' # ubs:ignore[ruby.lifecycle.file_handle]\n)\nhandle.read", ()),
    Case("wrong_rule_marker_keeps_obligation", "worker = Thread.new { work } # ubs:ignore[ruby.lifecycle.file_handle]", ((THREAD, 1),)),
    Case("string_marker_does_not_suppress_code", "worker = Thread.new { work }; note = '# ubs:ignore'", ((THREAD, 1),)),
    Case("marker_does_not_suppress_another_acquisition", "worker = Thread.new { first } # ubs:ignore[ruby.lifecycle.thread_join]\nsecond = Thread.new { second }", ((THREAD, 2),)),
    Case("acquisition_marker_does_not_suppress_double_finish", "session = Net::HTTP.start('example.com') # ubs:ignore[ruby.lifecycle.http_session]\nsession.finish\nsession.finish", ((HTTP, 3),)),
)

BY_NAME = {case.name: case for case in CASES}


class RubyLifecycleBindings(unittest.TestCase):
    def setUp(self):
        self.artifact = ROOT / "test-suite/artifacts/ruby-lifecycle-bindings" / (
            self._testMethodName + "-" + uuid.uuid4().hex[:12])
        self.artifact.mkdir(parents=True)

    def test_independent_binding_cases(self):
        for case in CASES:
            with self.subTest(case=case.name):
                started = time.monotonic()
                target = self.artifact / (case.name + ".rb")
                target.write_text(case.source, encoding="utf-8")
                actual = [("ruby.lifecycle." + kind, line_col(case.source, pos)[0])
                          for pos, kind, _ in lifecycle_ruby.scan_file(target, case.source)]
                (self.artifact / (case.name + ".json")).write_text(json.dumps({
                    "case": case.name, "expected": case.expected, "actual": actual,
                    "elapsed": time.monotonic() - started,
                    "source_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                    "analyzer_sha256": hashlib.sha256(Path(lifecycle_ruby.__file__).read_bytes()).hexdigest(),
                    "python": sys.version,
                }, indent=2) + "\n", encoding="utf-8")
                print(f"[{case.name}] {'PASS' if sorted(actual) == sorted(case.expected) else 'FAIL'} "
                      f"({time.monotonic() - started:.3f}s)", flush=True)
                self.assertEqual(sorted(actual), sorted(case.expected), case.source)

    def test_existing_managed_thread_fixture(self):
        target = ROOT / "test-suite/ruby/clean/performance.rb"
        source = target.read_text(encoding="utf-8")
        findings = lifecycle_ruby.scan_file(target, source)
        self.assertEqual([], findings)

    def test_analysis_limits_and_unsupported_shapes_are_explicit(self):
        cases = {
            "malformed": "worker = Thread.new do\n  work\n",
            "unsupported_closure": "worker = Thread.new { work }\ncallback = -> { worker.join }\n",
            "unknown_short_circuit": "worker = Thread.new { work }\nready && worker.join\n",
            "mutated_iterator": "workers = [Thread.new { work }]\nworkers.each { |worker| workers << Thread.new { work }; worker.join }\n",
            "path_budget": "\n".join(f"if ready{i}\n  worker{i} = Thread.new {{ work }}\nend" for i in range(9)),
            "unknown_loop_multiplicity": "workers = []\ncount.times { workers << Thread.new { work } }\nworkers[0].join\nworkers[1].join\n",
            "known_iteration_budget": "workers = []\n1000000.times { workers << Thread.new { work } }\nworkers.each(&:join)\n",
        }
        for name, source in cases.items():
            with self.subTest(case=name):
                target = self.artifact / (name + ".rb")
                target.write_text(source, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "incomplete") as caught:
                    lifecycle_ruby.scan_file(target, source)
                (self.artifact / (name + ".error.log")).write_text(str(caught.exception) + "\n", encoding="utf-8")
        # A comment or literal mentioning Thread.new does not authorize the
        # selected parser to reject otherwise unrelated dynamic Ruby syntax.
        source = "callback = -> { work }\nputs 'Thread.new'\n# File.open('data')\n"
        self.assertEqual([], lifecycle_ruby.scan_file(self.artifact / "unrelated.rb", source))

    def test_disabled_category_does_not_parse_unsupported_ownership(self):
        from ubs_core.ruby_scan import run_analyzers

        target = self.artifact / "unsupported.rb"
        target.write_text("worker = Thread.new { work }\ncallback = -> { worker.join }\n", encoding="utf-8")
        for disabled in (False, True):
            sink, errors = io.StringIO(), []
            run_analyzers([target], sink, skip={8} if disabled else set(), errors=errors)
            label = "disabled" if disabled else "enabled"
            (self.artifact / (label + ".ndjson")).write_text(sink.getvalue(), encoding="utf-8")
            (self.artifact / (label + ".errors.json")).write_text(json.dumps(errors) + "\n", encoding="utf-8")
            self.assertEqual(bool(errors), not disabled, errors)
            if errors:
                self.assertIn("lifecycle_ruby", errors[0])
                self.assertIn("incomplete", errors[0])
            try:
                records = [json.loads(line) for line in sink.getvalue().splitlines()]
            except json.JSONDecodeError as exc:
                self.fail(f"Invalid analyzer NDJSON: {exc}\n{sink.getvalue()}")
            self.assertFalse(any(row["rule"] in RULES for row in records), records)

    def public_lifecycle_json(self, label, target, expected_exit, *, disabled=False, flags=()):
        # This companion selects the resource category so exact totals do not
        # depend on optional Ruby tools or an installed ast-grep rule pack.
        skipped = ",".join(str(number) for number in range(1, 20) if number != 8 or disabled)
        command = [str(ROOT / "ubs"), "--only=ruby", "--ci", "--fail-on-warning",
                   "--format=json", "--skip-ruby=" + skipped, *flags, str(target)]
        env = {**os.environ, "UBS_NO_AUTO_UPDATE": "1", "UBS_ENABLE_AUTO_UPDATE": "0",
               "UBS_NO_CACHE": "0", "CI": "1", "NO_COLOR": "1",
               "UBS_CACHE_DIR": str(self.artifact / "cache")}
        start = time.monotonic()
        result = subprocess.run(command, cwd=self.artifact, env=env,
                                capture_output=True, text=True, timeout=180)
        (self.artifact / (label + ".stdout.log")).write_text(result.stdout, encoding="utf-8")
        (self.artifact / (label + ".stderr.log")).write_text(result.stderr, encoding="utf-8")
        sources = [target] if target.is_file() else sorted(target.glob("*.rb"))
        (self.artifact / (label + ".identity.json")).write_text(json.dumps({
            "command": command, "exit": result.returncode, "elapsed": time.monotonic() - start,
            "python": sys.version,
            "source_sha256": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
            "ubs_sha256": hashlib.sha256((ROOT / "ubs").read_bytes()).hexdigest(),
            "analyzer_sha256": hashlib.sha256(Path(lifecycle_ruby.__file__).read_bytes()).hexdigest(),
        }, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(result.returncode, expected_exit, (result.stdout, result.stderr))
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"Invalid public JSON: {exc}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        print(f"[ruby-lifecycle-{label}] PASS ({time.monotonic() - start:.3f}s)", flush=True)
        return report

    def test_public_selection_cache_suppression_and_incomplete_analysis(self):
        selected = self.artifact / "selected.rb"
        unrelated = self.artifact / "unselected.rb"
        selected.write_text(BY_NAME["direct_thread_join"].source, encoding="utf-8")
        unrelated.write_text(BY_NAME["direct_thread_leak"].source, encoding="utf-8")
        for label in ("cold", "warm"):
            report = self.public_lifecycle_json(label, selected, 0)
            self.assertEqual(report["status"], "ok", report)
            self.assertEqual(report["totals"], {"critical": 0, "warning": 0, "info": 0, "files": 1}, report)
            self.assertEqual(report["findings"], [], report)
            hits = report["scanners"][0]["extras"]["profile"]["cache_hits"]
            self.assertEqual(hits, int(label == "warm"), report)
        selected.write_text(BY_NAME["reassignment_drops_original_thread"].source, encoding="utf-8")
        report = self.public_lifecycle_json("changed-binding", selected, 1)
        self.assertEqual(report["totals"], {"critical": 0, "warning": 1, "info": 0, "files": 1}, report)
        self.assertEqual([(row["rule_id"], row["line"]) for row in report["findings"]], [(THREAD, 1)], report)
        self.assertEqual(report["scanners"][0]["extras"]["profile"]["cache_hits"], 0, report)
        selected.write_text("worker = Thread.new { work } # ubs:ignore[ruby.lifecycle.thread_join]\n", encoding="utf-8")
        report = self.public_lifecycle_json("suppressed", selected, 0)
        self.assertEqual(report["totals"], {"critical": 0, "warning": 0, "info": 0, "files": 1}, report)
        ignored = self.artifact / "exclude.txt"
        ignored.write_text("unselected.rb\n", encoding="utf-8")
        report = self.public_lifecycle_json("ignored", self.artifact, 0, flags=("--ignore-file=" + str(ignored),))
        self.assertEqual(report["totals"], {"critical": 0, "warning": 0, "info": 0, "files": 1}, report)
        selected.write_text("worker = Thread.new { work }\ncallback = -> { worker.join }\n", encoding="utf-8")
        report = self.public_lifecycle_json("disabled-category", selected, 0, disabled=True)
        self.assertEqual(report["status"], "ok", report)
        self.assertEqual(report["totals"], {"critical": 0, "warning": 0, "info": 0, "files": 1}, report)
        for label in ("partial-first", "partial-repeated"):
            report = self.public_lifecycle_json(label, self.artifact, 2)
            self.assertEqual(report["status"], "partial", report)
            self.assertEqual([(row["language"], row["status"], row["module_error"])
                              for row in report["failed_modules"]],
                             [("ruby", "partial", "ANALYZER_ERROR")], report)
            self.assertIn("lifecycle_ruby", report["failed_modules"][0]["message"])
            self.assertEqual(report["totals"], {"critical": 0, "warning": 1, "info": 0, "files": 2}, report)
            actual = [(Path(row["file"]).name, row["rule_id"], row["line"]) for row in report["findings"]]
            self.assertEqual(actual, [("unselected.rb", THREAD, 1)], report)
            self.assertIn("lifecycle_ruby", report["scanners"][0]["message"])

    def test_public_json_and_sarif(self):
        names = ("collection_joined_with_symbol", "unrelated_join_does_not_observe_anonymous_thread",
                 "uncalled_method_does_not_join_outer_thread", "collection_alias_retains_members",
                 "new_binding_does_not_discharge_old_thread", "conditional_join_leaves_obligation",
                 "file_alias_closes_original", "file_reassignment_keeps_old_obligation",
                 "ensure_closes_on_raise", "explicit_raise_skips_later_close")
        selected = self.artifact / "selected"
        selected.mkdir()
        expected = []
        for name in names:
            case = BY_NAME[name]
            (selected / (name + ".rb")).write_text(case.source, encoding="utf-8")
            expected.extend((name + ".rb", rule, line) for rule, line in case.expected)
        env = {**os.environ, "UBS_NO_AUTO_UPDATE": "1", "UBS_ENABLE_AUTO_UPDATE": "0",
               "CI": "1", "NO_COLOR": "1", "UBS_CACHE_DIR": str(self.artifact / "cache")}
        for fmt in ("json", "sarif"):
            with self.subTest(format=fmt):
                command = [str(ROOT / "ubs"), "--only=ruby", "--ci", "--fail-on-warning",
                           "--format=" + fmt, str(selected)]
                start = time.monotonic()
                result = subprocess.run(command, cwd=self.artifact, env=env,
                                        capture_output=True, text=True, timeout=180)
                (self.artifact / (fmt + ".stdout.log")).write_text(result.stdout, encoding="utf-8")
                (self.artifact / (fmt + ".stderr.log")).write_text(result.stderr, encoding="utf-8")
                (self.artifact / (fmt + ".identity.json")).write_text(json.dumps({
                    "command": command, "exit": result.returncode, "elapsed": time.monotonic() - start,
                    "python": sys.version,
                    "ubs_sha256": hashlib.sha256((ROOT / "ubs").read_bytes()).hexdigest(),
                    "analyzer_sha256": hashlib.sha256(Path(lifecycle_ruby.__file__).read_bytes()).hexdigest(),
                }, indent=2) + "\n", encoding="utf-8")
                self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
                try:
                    payload = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    self.fail(f"Invalid public {fmt}: {exc}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
                if fmt == "json":
                    self.assertEqual(payload["status"], "ok", payload)
                    self.assertEqual(payload["failed_modules"], [], payload)
                    self.assertEqual(payload["totals"]["files"], len(names), payload)
                    actual = [(Path(row["file"]).name, row["rule_id"], row["line"])
                              for row in payload["findings"] if row["rule_id"] in RULES]
                else:
                    actual = [(Path(row["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]).name,
                               row["ruleId"], row["locations"][0]["physicalLocation"]["region"]["startLine"])
                              for run in payload["runs"] for row in run.get("results", []) if row["ruleId"] in RULES]
                self.assertEqual(sorted(actual), sorted(expected), payload)
                print(f"[ruby-lifecycle-public-{fmt}] PASS ({time.monotonic() - start:.3f}s)", flush=True)


if __name__ == "__main__":
    unittest.main()
