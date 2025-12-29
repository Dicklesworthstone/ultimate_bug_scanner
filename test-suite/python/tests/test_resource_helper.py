#!/usr/bin/env python3
"""Regression tests for the Python resource lifecycle helper."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
HELPER = REPO_ROOT / "modules" / "helpers" / "resource_lifecycle_py.py"


def run_helper(source_map: dict[str, str]) -> list[str]:
    tmpdir = Path(tempfile.mkdtemp(prefix="ubs-resource-helper-"))
    try:
        for rel, code in source_map.items():
            path = tmpdir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(code), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(HELPER), str(tmpdir)],
            capture_output=True,
            text=True,
            check=False,
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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
