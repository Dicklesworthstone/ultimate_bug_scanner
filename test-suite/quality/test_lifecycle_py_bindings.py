"""Resource-identity regressions for the Python lifecycle analyzer.

Run: python3 -B -m unittest discover -s test-suite/quality -p 'test_lifecycle_py_bindings.py' -v
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "helpers"))

from ubs_core.analyzers.lifecycle_py import SELF_TESTS, _collect_unreleased
from ubs_core.registry import RunContext, run_layer


class LifecycleBindingsTests(unittest.TestCase):
    def run(self, result=None):
        started = time.monotonic()
        print(f"[{self.id()}] RUN", flush=True)
        if result is None:
            result = self.defaultTestResult()
        failures_before = len(result.failures) + len(result.errors)
        outcome = super().run(result)
        failed = len(outcome.failures) + len(outcome.errors) > failures_before
        print(f"[{self.id()}] {'FAIL' if failed else 'PASS'} ({time.monotonic() - started:.3f}s)", flush=True)
        return outcome

    def assertLeaks(self, code, expected):
        code = textwrap.dedent(code).strip() + "\n"
        found = [(rec.kind, rec.lineno) for rec in _collect_unreleased(code)]
        self.assertEqual(expected, found, msg=f"Source:\n{code}\nActual findings: {found!r}")

    def test_each_resource_uses_its_own_release_methods(self):
        for source in (
            "handle = open('x')\nhandle.close()",
            "import socket\nhandle = socket.socket()\nhandle.close()",
            "import subprocess\nhandle = subprocess.Popen(['true'])\nhandle.wait()",
            "import asyncio\nhandle = asyncio.create_task(work())\nhandle.cancel()",
        ):
            with self.subTest(source=source):
                self.assertLeaks(source, [])

    def test_repeated_close_does_not_release_overwritten_acquisition(self):
        self.assertLeaks("handle = open('first')\nhandle = open('second')\nhandle.close()\nhandle.close()", [("file_handle", 1)])

    def test_repeated_await_does_not_release_overwritten_task(self):
        self.assertLeaks("""
            import asyncio
            async def run():
                task = asyncio.create_task(first())
                task = asyncio.create_task(second())
                await task
                await task
        """, [("asyncio_task", 3)])

    def test_rebinding_to_another_kind_does_not_close_the_old_kind(self):
        self.assertLeaks("import socket\nhandle = open('x')\nhandle = socket.socket()\nhandle.close()", [("file_handle", 2)])

    def test_rebinding_to_unknown_value_keeps_old_resource_unreleased(self):
        self.assertLeaks("handle = open('x')\nhandle = get_other_handle()\nhandle.close()", [("file_handle", 1)])

    def test_rhs_cleanup_happens_before_rebinding(self):
        self.assertLeaks("handle = open('x')\nhandle = handle.close()", [])

    def test_simple_alias_cleanup_releases_the_same_resource(self):
        self.assertLeaks("handle = open('x')\nalias = handle\nalias.close()", [])

    def test_alias_survives_original_name_rebinding(self):
        self.assertLeaks("handle = open('first')\nalias = handle\nhandle = open('second')\nalias.close()\nhandle.close()", [])

    def test_alias_cleanup_does_not_release_the_new_binding(self):
        self.assertLeaks("handle = open('first')\nalias = handle\nhandle = open('second')\nalias.close()", [("file_handle", 3)])

    def test_chained_assignment_has_one_resource_identity(self):
        self.assertLeaks("first = second = open('x')\nsecond.close()", [])
        self.assertLeaks("first = second = open('x')", [("file_handle", 1)])

    def test_tuple_assignment_keeps_distinct_resources(self):
        self.assertLeaks("left, right = open('left'), open('right')\nleft.close()\nright.close()", [])
        self.assertLeaks("left, right = open('left'), open('right')\nleft.close()", [("file_handle", 1)])

    def test_parallel_assignment_snapshots_rhs_bindings(self):
        self.assertLeaks("left = open('left')\nright = open('right')\nleft, right = right, left\nleft.close()", [("file_handle", 1)])

    def test_socketpair_endpoints_are_independent(self):
        self.assertLeaks("import socket\nleft, right = socket.socketpair()\nleft.close()", [("socket_handle", 2)])
        self.assertLeaks("import socket\nleft, right = socket.socketpair()\nleft.close()\nright.close()", [])

    def test_annotated_alias_keeps_resource_identity(self):
        self.assertLeaks("handle = open('x')\nalias: object = handle\nalias.close()", [])

    def test_named_expression_keeps_resource_identity(self):
        self.assertLeaks("(handle := open('x')).close()", [])

    def test_delete_invalidates_the_binding_but_not_other_aliases(self):
        self.assertLeaks("handle = open('x')\ndel handle\nhandle.close()", [("file_handle", 1)])
        self.assertLeaks("handle = open('x')\nalias = handle\ndel handle\nalias.close()", [])

    def test_starred_unpacking_keeps_endpoint_identity(self):
        self.assertLeaks("first, *rest = [open('a'), open('b')]\nlast, = rest\nfirst.close()\nlast.close()", [])

    def test_attribute_alias_cleanup(self):
        self.assertLeaks("holder.handle = open('x')\nalias = holder.handle\nalias.close()", [])

    def test_rebinding_object_invalidates_its_tracked_attributes(self):
        self.assertLeaks("holder.handle = open('x')\nholder = other\nholder.handle.close()", [("file_handle", 1)])

    def test_uncalled_function_cannot_release_outer_resource(self):
        self.assertLeaks("handle = open('x')\ndef cleanup():\n    handle.close()", [("file_handle", 1)])

    def test_uncalled_lambda_cannot_release_outer_resource(self):
        self.assertLeaks("handle = open('x')\ncleanup = lambda: handle.close()", [("file_handle", 1)])

    def test_called_closure_releases_enclosing_resource(self):
        # test_resource_helper's nested-scope case: inner() runs the close.
        self.assertLeaks("""
            import asyncio
            def outer():
                fh = open('x')
                async def inner():
                    fh.close()
                asyncio.run(inner())
        """, [])
        self.assertLeaks("handle = open('x')\ndef cleanup():\n    handle.close()\ncleanup()", [])

    def test_uncalled_closure_does_not_release_enclosing_resource(self):
        self.assertLeaks("handle = open('x')\ndef cleanup():\n    handle.close()", [("file_handle", 1)])
        self.assertLeaks("""
            def outer():
                fh = open('x')
                def inner():
                    fh.close()
                return 1
        """, [("file_handle", 2)])

    def test_same_named_inner_binding_does_not_release_outer(self):
        self.assertLeaks("""
            handle = open('outer')
            def inner():
                handle = open('inner')
                handle.close()
                handle.close()
        """, [("file_handle", 1)])

    def test_function_arguments_do_not_release_outer_resources(self):
        self.assertLeaks("handle = open('outer')\ndef inner(handle):\n    handle.close()", [("file_handle", 1)])

    def test_nested_function_still_resolves_imported_factories(self):
        self.assertLeaks("""
            from socket import socket as make_socket
            def outer():
                def inner():
                    handle = make_socket()
                    handle.close()
        """, [])

    def test_direct_factory_cleanup_still_works(self):
        self.assertLeaks("open('x').close()\nimport socket\nsocket.socket().close()", [])

    def test_with_existing_handle_and_alias_closes_that_identity(self):
        self.assertLeaks("handle = open('x')\nwith handle as alias:\n    alias.read()", [])

    def test_with_cleanup_does_not_follow_rebinding_inside_body(self):
        self.assertLeaks("handle = open('first')\nwith handle:\n    handle = open('second')", [("file_handle", 3)])

    def test_unknown_with_target_cannot_close_a_previous_binding(self):
        self.assertLeaks("handle = open('x')\nwith unrelated() as handle:\n    handle.close()", [("file_handle", 1)])

    def test_contextlib_closing_supports_import_and_resource_aliases(self):
        for wrapper in ("import contextlib\nwith contextlib.closing(handle):", "from contextlib import closing as managed\nwith managed(handle):"):
            with self.subTest(wrapper=wrapper):
                self.assertLeaks("handle = open('x')\n" + wrapper + "\n    pass", [])

    def test_stored_context_manager_keeps_its_owned_resource(self):
        self.assertLeaks("from contextlib import closing\nhandle = open('x')\nmanager = closing(handle)\nhandle = other\nwith manager:\n    pass", [])
        self.assertLeaks("from contextlib import closing\nmanager = closing(open('x'))", [("file_handle", 2)])

    def test_unknown_context_manager_does_not_own_arbitrary_arguments(self):
        self.assertLeaks("with unrelated(open('x')):\n    pass", [("file_handle", 1)])

    def test_nullcontext_does_not_close_its_value(self):
        self.assertLeaks("from contextlib import nullcontext\nwith nullcontext(open('x')) as handle:\n    pass", [("file_handle", 2)])
        self.assertLeaks("from contextlib import nullcontext\nwith nullcontext(open('x')) as handle:\n    handle.close()", [])

    def test_context_manager_owns_only_its_result_not_nested_acquisitions(self):
        self.assertLeaks("with open('x', opener=make_opener(open('config'))):\n    pass", [("file_handle", 1)])

    def test_with_method_result_does_not_close_receiver(self):
        self.assertLeaks("with open('x').read():\n    pass", [("file_handle", 1)])

    def test_synchronous_resources_are_not_async_context_managers(self):
        self.assertLeaks("async def run():\n    async with open('x'):\n        pass", [("file_handle", 2)])

    def test_native_socket_and_process_context_managers(self):
        self.assertLeaks("import socket\nhandle = socket.socket()\nwith handle:\n    pass", [])
        self.assertLeaks("import subprocess\nhandle = subprocess.Popen(['true'])\nwith handle:\n    pass", [])

    def test_shutdown_is_not_socket_close(self):
        self.assertLeaks("import socket\nhandle = socket.socket()\nhandle.shutdown(socket.SHUT_RDWR)", [("socket_handle", 2)])
        self.assertLeaks("import socket\nhandle = socket.socket()\nhandle.shutdown(socket.SHUT_RDWR)\nhandle.close()", [])

    def test_signalling_a_process_does_not_reap_it(self):
        for method in ("kill", "terminate"):
            with self.subTest(method=method):
                code = f"import subprocess\nhandle = subprocess.Popen(['true'])\nhandle.{method}()"
                self.assertLeaks(code, [("popen_handle", 2)])
                self.assertLeaks(code + "\nhandle.wait()", [])

    def assertTaskLeaks(self, body, expected):
        prefix = "import asyncio\nasync def run():\n    task = asyncio.create_task(work())\n"
        self.assertLeaks(prefix + textwrap.indent(textwrap.dedent(body).strip(), "    "), expected)

    def test_unawaited_supervisors_do_not_release_tasks(self):
        for call in ("asyncio.gather(task)", "asyncio.wait([task])", "asyncio.wait_for(task, 1)"):
            with self.subTest(call=call):
                self.assertTaskLeaks(call, [("asyncio_task", 3)])

    def test_awaited_supervisors_release_their_inputs(self):
        for call in ("asyncio.gather(task)", "asyncio.wait([task])", "asyncio.wait_for(task, 1)"):
            with self.subTest(call=call):
                self.assertTaskLeaks("await " + call, [])

    def test_stored_supervisor_is_only_effective_when_awaited(self):
        self.assertTaskLeaks("group = asyncio.gather(task)", [("asyncio_task", 3)])
        self.assertTaskLeaks("group = asyncio.gather(task)\nawait group", [])
        self.assertTaskLeaks("group = asyncio.gather(task)\nalias = group\ngroup = other\nawait alias", [])

    def test_supervisor_snapshots_task_identity_before_rebinding(self):
        self.assertTaskLeaks("group = asyncio.gather(task)\ntask = asyncio.create_task(other())\nawait group", [("asyncio_task", 5)])

    def test_awaiting_a_list_is_not_awaiting_its_tasks(self):
        self.assertTaskLeaks("tasks = [task]\nawait tasks", [("asyncio_task", 3)])

    def test_invalid_gather_list_argument_does_not_release_tasks(self):
        self.assertTaskLeaks("await asyncio.gather([task])", [("asyncio_task", 3)])

    def test_starred_gather_and_wait_containers(self):
        for body in ("tasks = [task]\nawait asyncio.gather(*tasks)", "tasks = (task,)\nawait asyncio.wait(tasks)", "await asyncio.wait({task})"):
            with self.subTest(body=body):
                self.assertTaskLeaks(body, [])

    def test_configuration_keywords_are_not_task_arguments(self):
        for body in ("await asyncio.gather(return_exceptions=task)", "await asyncio.wait_for(work(), timeout=task)"):
            with self.subTest(body=body):
                self.assertTaskLeaks(body, [("asyncio_task", 3)])

    def test_task_arguments_may_be_passed_by_keyword(self):
        self.assertTaskLeaks("await asyncio.wait_for(fut=task, timeout=1)", [])
        self.assertTaskLeaks("await asyncio.wait(fs=[task])", [])

    def test_invalid_wait_for_arguments_do_not_prove_supervision(self):
        for arguments in ("task", "task, 1, timeout=2", "task, fut=task, timeout=1"):
            with self.subTest(arguments=arguments):
                self.assertTaskLeaks(f"await asyncio.wait_for({arguments})", [("asyncio_task", 3)])

    def test_wait_timeout_or_partial_completion_leaves_pending_tasks(self):
        for options in ("timeout=0", "timeout=deadline", "return_when=asyncio.FIRST_COMPLETED", "return_when=asyncio.FIRST_EXCEPTION", "**options"):
            with self.subTest(options=options):
                self.assertTaskLeaks(f"await asyncio.wait([task], {options})", [("asyncio_task", 3)])

    def test_wait_all_completed_with_no_timeout_is_observed(self):
        self.assertTaskLeaks("await asyncio.wait([task], timeout=None, return_when=asyncio.ALL_COMPLETED)", [])
        self.assertTaskLeaks("from asyncio import ALL_COMPLETED as complete\nawait asyncio.wait([task], return_when=complete)", [])

    def test_invalid_wait_input_is_not_supervision(self):
        self.assertTaskLeaks("await asyncio.wait(task)", [("asyncio_task", 3)])

    def test_nested_awaited_supervisors(self):
        self.assertTaskLeaks("await asyncio.gather(asyncio.wait_for(task, 1))", [])
        self.assertTaskLeaks("asyncio.gather(asyncio.wait_for(task, 1))", [("asyncio_task", 3)])

    def test_deep_shared_supervisor_graph_is_not_recursively_expanded(self):
        lines = ["group = task"]
        lines.extend("group = asyncio.gather(group, group)" for _ in range(1200))
        lines.append("await group")
        self.assertTaskLeaks("\n".join(lines), [])

    def test_cancelling_gather_cancels_children_but_coroutine_cancel_is_not_valid(self):
        self.assertTaskLeaks("group = asyncio.gather(task)\ngroup.cancel()", [])
        self.assertTaskLeaks("group = asyncio.wait_for(task, 1)\ngroup.cancel()", [("asyncio_task", 3)])

    def test_existing_selftests(self):
        for name, check in SELF_TESTS:
            with self.subTest(name=name):
                check()

    def test_shadowed_builtin_open_is_not_a_known_factory(self):
        for code in (
            "open = custom_factory\nhandle = open('x')",
            "def run(open):\n    handle = open('x')",
            "def open(path):\n    return custom_factory(path)\nhandle = open('x')",
            "class open:\n    pass\nhandle = open('x')",
        ):
            with self.subTest(code=code):
                self.assertLeaks(code, [])

    def test_shadowed_imported_factory_is_not_a_known_factory(self):
        self.assertLeaks("from io import open as reader\nreader = custom_factory\nhandle = reader('x')", [])

    def test_aliases_of_known_factories_are_detected(self):
        self.assertLeaks("import io\nreader = io.open\nhandle = reader('x')", [("file_handle", 3)])
        self.assertLeaks("reader = open\nhandle = reader('x')\nhandle.close()", [])

    def test_qualified_factory_resolves_module_aliases(self):
        self.assertLeaks("import pathlib as paths\nhandle = paths.Path.open(path)", [("file_handle", 2)])
        self.assertLeaks("from pathlib import Path as P\nhandle = P('x').open()\nhandle.close()", [])

    def test_aliases_of_task_supervisors_are_observed(self):
        self.assertTaskLeaks("join = asyncio.gather\nawait join(task)", [])
        self.assertTaskLeaks("join = asyncio.gather\njoin = unrelated\nawait join(task)", [("asyncio_task", 3)])

    def test_rebound_module_does_not_supply_a_trusted_supervisor(self):
        self.assertLeaks("""
            async def run():
                import asyncio
                task = asyncio.create_task(work())
                asyncio = other_library
                await asyncio.gather(task)
        """, [("asyncio_task", 3)])

    def test_rebound_module_attribute_does_not_supply_a_trusted_supervisor(self):
        self.assertTaskLeaks("asyncio.gather = unrelated\nawait asyncio.gather(task)", [("asyncio_task", 3)])

    def test_import_replaces_an_existing_resource_binding(self):
        self.assertLeaks("handle = open('x')\nimport fileinput as handle\nhandle.close()", [("file_handle", 1)])

    def test_function_definition_replaces_a_resource_binding(self):
        self.assertLeaks("handle = open('x')\ndef handle():\n    pass\nhandle.close()", [("file_handle", 1)])

    def test_function_defaults_execute_in_the_surrounding_scope(self):
        self.assertLeaks("handle = open('x')\ndef run(value=handle.close()):\n    pass", [])
        self.assertLeaks("def run(handle=open('x')):\n    handle.close()", [("file_handle", 1)])

    def test_lambda_defaults_execute_in_the_surrounding_scope(self):
        self.assertLeaks("handle = open('x')\nrun = lambda value=handle.close(): None", [])

    def test_local_imports_do_not_escape_a_class_body(self):
        self.assertLeaks("reader = custom_factory\nclass Config:\n    from io import open as reader\nhandle = reader('x')", [])

    def test_methods_do_not_look_up_free_names_in_the_class_namespace(self):
        self.assertLeaks("""
            import asyncio
            class Runner:
                asyncio = other_library
                async def run(self):
                    task = asyncio.create_task(work())
        """, [("asyncio_task", 5)])

    def test_executed_class_body_can_close_an_outer_resource(self):
        self.assertLeaks("handle = open('x')\nclass Config:\n    handle.close()", [])

    def test_class_bindings_do_not_replace_surrounding_bindings(self):
        self.assertLeaks("handle = open('outer')\nclass Config:\n    handle = open('inner')\n    handle.close()\nhandle.close()", [])

    def test_nested_function_sees_lexical_shadowing_even_before_assignment(self):
        self.assertLeaks("""
            def outer():
                def inner():
                    handle = open('x')
                open = custom_factory
                return inner
        """, [])

    def test_global_declaration_bypasses_an_outer_local_shadow(self):
        self.assertLeaks("""
            import io as reader
            def outer():
                reader = custom_factory
                def inner():
                    global reader
                    handle = reader.open('x')
        """, [("file_handle", 6)])

    def test_function_local_shadow_does_not_change_module_import(self):
        self.assertLeaks("""
            import socket
            def inner():
                socket = custom_library
                handle = socket.socket()
            handle = socket.socket()
        """, [("socket_handle", 5)])

    def test_relative_imports_do_not_impersonate_standard_library_factories(self):
        self.assertLeaks("from .socket import socket as create\nhandle = create()", [])
        self.assertLeaks("from . import socket\nhandle = socket.socket()", [])

    def test_structured_and_legacy_entrypoints_agree(self):
        artifacts = ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="lifecycle-bindings-", dir=artifacts))
        source = work / "fixture.py"
        source.write_text("import socket\nsock = socket.socket()\nsock.close()\nfirst = open('a')\nfirst = open('b')\nfirst.close()\nfirst.close()\n", encoding="utf-8")
        findings = list(run_layer("lifecycle", RunContext(lang="python", files=[source])))
        (work / "result.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
        self.assertEqual([("python.lifecycle.file_handle", 4, "critical")], [(r["rule"], r["line"], r["severity"]) for r in findings])
        command = [sys.executable, "-B", str(ROOT / "modules/helpers/resource_lifecycle_py.py"), str(work)]
        proc = subprocess.run(command, text=True, capture_output=True, timeout=15, cwd=work)
        (work / "stdout.log").write_text(proc.stdout, encoding="utf-8")
        (work / "stderr.log").write_text(proc.stderr, encoding="utf-8")
        self.assertEqual(0, proc.returncode, msg=proc.stdout + proc.stderr)
        self.assertEqual("", proc.stderr)
        self.assertEqual(1, len(proc.stdout.splitlines()), msg=proc.stdout)
        self.assertIn("fixture.py:4\tfile_handle\t", proc.stdout)


if __name__ == "__main__":
    unittest.main()
