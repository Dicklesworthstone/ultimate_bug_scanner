#!/usr/bin/env python3
"""Regression tests for the Java resource lifecycle helper."""
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
HELPER = REPO_ROOT / "modules" / "helpers" / "resource_lifecycle_java.py"


class JavaResourceHelperTests(unittest.TestCase):
    def run_helper(self, sources: dict[str, str]) -> list[str]:
        temp_dir = Path(tempfile.mkdtemp(prefix="ubs-java-helper-"))
        try:
            for rel, code in sources.items():
                path = temp_dir / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(textwrap.dedent(code), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(HELPER), str(temp_dir)],
                capture_output=True,
                text=True,
                check=False,
                # An AST helper over a handful of fixture files takes a second
                # or two; without a deadline a hung helper hangs the suite with
                # no diagnostic (#123). An expiry raises, which is a failure.
                timeout=int(os.environ.get("UBS_TEST_CHILD_TIMEOUT", "120")),
            )
            return [line for line in result.stdout.splitlines() if line.strip()]
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_detects_statement_and_callable_leaks(self) -> None:
        lines = self.run_helper(
            {
                "Leak.java": """
                import java.sql.*;
                public class Leak {
                    void bad(Connection conn) throws Exception {
                        Statement stmt = conn.createStatement();
                        PreparedStatement ps = conn.prepareStatement("select 1");
                        CallableStatement call = conn.prepareCall("{ call bump(?) }");
                        ResultSet rs = stmt.executeQuery("SELECT NOW()");
                        System.out.println(rs.getMetaData());
                    }
                }
                """,
            }
        )
        kinds = {line.split("\t")[1] for line in lines}
        self.assertIn("statement_handle", kinds)
        self.assertIn("resultset_handle", kinds)

    def test_try_with_resources_is_suppressed(self) -> None:
        lines = self.run_helper(
            {
                "Clean.java": """
                import java.sql.*;
                public class Clean {
                    void tidy(Connection conn) throws Exception {
                        try (Statement stmt = conn.createStatement();
                             PreparedStatement ps = conn.prepareStatement("select 1");
                             CallableStatement call = conn.prepareCall("{ call bump(?) }");
                             ResultSet rs = stmt.executeQuery("SELECT NOW()")) {
                            call.execute();
                        }
                    }
                }
                """,
            }
        )
        self.assertEqual(lines, [])

    def test_ignores_commented_out_handles(self) -> None:
        lines = self.run_helper(
            {
                "Commented.java": """
                import java.sql.*;
                class Commented {
                    void noop(Connection conn) throws Exception {
                        // PreparedStatement stmt = conn.prepareStatement("select 1");
                        /* ResultSet rs = stmt.executeQuery(); */
                    }
                }
                """,
            }
        )
        self.assertEqual(lines, [])

    def test_string_literals_with_slashes_are_not_comments(self) -> None:
        lines = self.run_helper(
            {
                "Strings.java": """
                import java.sql.*;
                class Strings {
                    void noop(Connection conn) throws Exception {
                        String text = "Statement stmt = conn.createStatement();";
                        System.out.println(text);
                    }
                }
                """,
            }
        )
        self.assertEqual(lines, [])

    def test_text_blocks_are_ignored(self) -> None:
        lines = self.run_helper(
            {
                "TextBlock.java": """
                import java.sql.*;
                class TextBlock {
                    void noop(Connection conn) {
                        String sql = \"\"\"
                            Statement stmt = conn.createStatement();
                        \"\"\";
                        System.out.println(sql);
                    }
                }
                """,
            }
        )
        self.assertEqual(lines, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
