#!/usr/bin/env python3
"""Regression tests for helper-backed resource lifecycle analyzers."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
PYTHON_HELPER = REPO_ROOT / "modules" / "helpers" / "resource_lifecycle_py.py"
CPP_HELPER = REPO_ROOT / "modules" / "helpers" / "resource_lifecycle_cpp.py"
RUBY_HELPER = REPO_ROOT / "modules" / "helpers" / "resource_lifecycle_ruby.py"
SWIFT_HELPER = REPO_ROOT / "modules" / "helpers" / "resource_lifecycle_swift.py"


def run_helper(helper: Path, source_map: dict[str, str], *, prefix: str = "ubs-resource-helper-") -> list[str]:
    tmpdir = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        for rel, code in source_map.items():
            path = tmpdir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(code), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(helper), str(tmpdir)],
            capture_output=True,
            text=True,
            check=False,
            # The helper is the only child this harness spawns — the
            # `subprocess.Popen(["sleep", …])` calls below are fixture *text*
            # for the scanner to analyse, not children of this process. An
            # unbounded wait here would turn a hung helper into a silent hang
            # (#123).
            timeout=int(os.environ.get("UBS_TEST_CHILD_TIMEOUT", "120")),
        )
        return [line for line in result.stdout.strip().splitlines() if line.strip()]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def parse(lines: list[str]) -> list[tuple[str, str, str]]:
    entries: list[tuple[str, str, str]] = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) >= 3:
            entries.append((parts[0], parts[1], parts[2]))
    return entries


class ResourceHelperTests(unittest.TestCase):
    def test_reports_leaks_across_kinds(self) -> None:
        lines = run_helper(
            PYTHON_HELPER,
            {
                "leaky.py": """
                import asyncio
                import socket
                import subprocess

                def leak_everything():
                    fh = open("/tmp/demo.txt", "w")
                    sock = socket.socket()
                    proc = subprocess.Popen(["sleep", "1"])

                    async def go():
                        task = asyncio.create_task(asyncio.sleep(1))
                        await asyncio.sleep(0.1)
                        return task

                    asyncio.run(go())
                    return fh, sock, proc
                """,
            }
        )
        entries = parse(lines)
        kinds = {kind for _, kind, _ in entries}
        self.assertIn("file_handle", kinds)
        self.assertIn("socket_handle", kinds)
        self.assertIn("popen_handle", kinds)
        self.assertIn("asyncio_task", kinds)

    def test_release_in_nested_scope_marks_outer_resource(self) -> None:
        lines = run_helper(
            PYTHON_HELPER,
            {
                "nested.py": """
                import asyncio

                def outer():
                    fh = open("/tmp/demo.txt", "w")

                    async def inner():
                        fh.close()

                    asyncio.run(inner())
                """,
            }
        )
        self.assertEqual(lines, [])

    def test_reassignment_marks_latest_resource_as_released(self) -> None:
        lines = run_helper(
            PYTHON_HELPER,
            {
                "reassign.py": """
                def demo():
                    fh = open("/tmp/a.txt", "w")
                    fh = open("/tmp/b.txt", "w")
                    fh.close()
                """,
            }
        )
        entries = parse(lines)
        self.assertEqual(len(entries), 1)
        loc, kind, _ = entries[0]
        self.assertIn("reassign.py", loc)
        self.assertTrue(loc.endswith(":3"), loc)
        self.assertEqual(kind, "file_handle")

    def test_clean_project_stays_quiet(self) -> None:
        lines = run_helper(
            PYTHON_HELPER,
            {
                "clean.py": """
                import asyncio
                import socket
                import subprocess

                def tidy():
                    with open("/tmp/demo.txt", "w", encoding="utf-8") as fh:
                        fh.write("ok")
                    with socket.socket() as sock:
                        sock.connect(("localhost", 9))
                    proc = subprocess.Popen(["sleep", "0"], stdin=subprocess.PIPE)
                    proc.wait()

                    async def runner():
                        task = asyncio.create_task(asyncio.sleep(0))
                        await task
                    asyncio.run(runner())
                """,
            }
        )
        self.assertEqual(lines, [])

    def test_chained_cleanup_does_not_report(self) -> None:
        lines = run_helper(
            PYTHON_HELPER,
            {
                "chained.py": """
                import asyncio
                import socket
                import subprocess

                def tidy():
                    open("/tmp/demo.txt", "w").close()
                    socket.socket().close()
                    subprocess.Popen(["sleep", "0"]).wait()

                async def runner():
                    await asyncio.create_task(asyncio.sleep(0))
                    await asyncio.gather(asyncio.create_task(asyncio.sleep(0)))
                    asyncio.create_task(asyncio.sleep(0)).cancel()

                asyncio.run(runner())
                """,
            }
        )
        self.assertEqual(lines, [])

    def test_ruby_helper_reports_resource_leaks(self) -> None:
        lines = run_helper(
            RUBY_HELPER,
            {
                "leaky.rb": """
                require "net/http"

                worker = Thread.new do
                  sleep 0.1
                end

                file = File.open("/tmp/demo.txt", "w")
                file.write("hi")

                http = Net::HTTP.start("example.com", 80)
                puts worker
                puts file
                puts http
                """,
            },
            prefix="ubs-ruby-resource-helper-",
        )
        entries = parse(lines)
        kinds = {kind for _, kind, _ in entries}
        self.assertIn("thread_join", kinds)
        self.assertIn("file_handle", kinds)
        self.assertIn("http_session", kinds)

    def test_ruby_helper_respects_cleanup(self) -> None:
        lines = run_helper(
            RUBY_HELPER,
            {
                "clean.rb": """
                require "net/http"

                worker = Thread.new do
                  sleep 0.1
                end
                worker.join

                file = File.open("/tmp/demo.txt", "w")
                file.write("ok")
                file.close

                http = Net::HTTP.start("example.com", 80)
                http.finish
                """,
            },
            prefix="ubs-ruby-resource-helper-",
        )
        self.assertEqual(lines, [])

    def test_cpp_helper_reports_resource_leaks(self) -> None:
        lines = run_helper(
            CPP_HELPER,
            {
                "leaky.cpp": """
                #include <cstdio>
                #include <cstdlib>
                #include <thread>

                void work() {}

                void leak_everything() {
                    std::thread worker(work);
                    void* buf = malloc(256);
                    FILE* handle = fopen("/tmp/demo.txt", "w");
                    (void)worker;
                    (void)buf;
                    (void)handle;
                }
                """,
            },
            prefix="ubs-cpp-resource-helper-",
        )
        entries = parse(lines)
        kinds = {kind for _, kind, _ in entries}
        self.assertIn("thread_join", kinds)
        self.assertIn("malloc_heap", kinds)
        self.assertIn("fopen_handle", kinds)

    def test_cpp_helper_respects_cleanup(self) -> None:
        lines = run_helper(
            CPP_HELPER,
            {
                "clean.cpp": """
                #include <cstdio>
                #include <cstdlib>
                #include <thread>

                void work() {}

                void tidy() {
                    std::thread worker(work);
                    worker.join();

                    void* buf = malloc(256);
                    free(buf);

                    FILE* handle = fopen("/tmp/demo.txt", "w");
                    fclose(handle);
                }
                """,
            },
            prefix="ubs-cpp-resource-helper-",
        )
        self.assertEqual(lines, [])

    def test_swift_helper_reports_resource_leaks(self) -> None:
        lines = run_helper(
            SWIFT_HELPER,
            {
                "Leaky.swift": """
                import Foundation

                func leakEverything(url: URL, session: URLSession, publisher: AnyObject) {
                    let task = session.dataTask(with: url)
                    let timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in }
                    let handle = try! FileHandle(forWritingTo: url)
                    let link = CADisplayLink(target: NSObject(), selector: #selector(NSObject.description))
                    _ = publisher.sink { _ in }
                    print(task, timer, handle, link)
                }
                """,
            },
            prefix="ubs-swift-resource-helper-",
        )
        entries = parse(lines)
        kinds = {kind for _, kind, _ in entries}
        self.assertIn("urlsession_task", kinds)
        self.assertIn("timer", kinds)
        self.assertIn("file_handle", kinds)
        self.assertIn("cadisplaylink", kinds)

    def test_swift_helper_respects_cleanup(self) -> None:
        lines = run_helper(
            SWIFT_HELPER,
            {
                "Clean.swift": """
                import Foundation

                func tidy(url: URL, session: URLSession) {
                    let task = session.dataTask(with: url)
                    task.resume()
                    let timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: false) { _ in }
                    timer.invalidate()
                    let handle = try! FileHandle(forWritingTo: url)
                    try? handle.close()
                    let link = CADisplayLink(target: NSObject(), selector: #selector(NSObject.description))
                    link.invalidate()
                }
                """,
            },
            prefix="ubs-swift-resource-helper-",
        )
        self.assertEqual(lines, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
