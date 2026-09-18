#!/usr/bin/env python3
"""Regression tests for the C# helper analyzers."""
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
TYPE_HELPER = REPO_ROOT / "modules" / "helpers" / "type_narrowing_csharp.py"
RESOURCE_HELPER = REPO_ROOT / "modules" / "helpers" / "resource_lifecycle_csharp.py"
ASYNC_HELPER = REPO_ROOT / "modules" / "helpers" / "async_task_handles_csharp.py"


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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
