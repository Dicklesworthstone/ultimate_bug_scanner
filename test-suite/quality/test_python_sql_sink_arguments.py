#!/usr/bin/env python3
"""Independent SQL argument-position and predicate regressions.

Run directly with Python, or through unittest discovery. Fixtures are parsed by
UBS, not executed against a database. Their expected public IDs and locations
come from API argument semantics, not from another detector implementation.

API contracts:
https://www.psycopg.org/psycopg3/docs/api/cursors.html
https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.read_sql.html
https://docs.sqlalchemy.org/en/20/core/connections.html
https://docs.djangoproject.com/en/5.2/ref/models/querysets/#extra

Artifacts are intentionally retained beneath test-suite/artifacts/.
"""
from __future__ import annotations

import hashlib
import ast
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "helpers"))
from ubs_core.py_detectors import sql_injection as detector

CRITICAL = "py.security.sql-injection"
WARNING = "py.security.sql-injection-unproven"

# Each case has a unique source file. The sink starts at line 2 unless a case
# explicitly supplies a multi-line program and its expected location.
CASES = (
    ("psycopg-query", 'def run(cursor, user):\n    cursor.execute(query=f"SELECT * FROM users WHERE name = {user}")\n', ((CRITICAL, 2),)),
    ("psycopg-many", 'def run(cursor, user, rows):\n    cursor.executemany(query=f"INSERT INTO users VALUES ({user}, %s)", params_seq=rows)\n', ((CRITICAL, 2),)),
    ("sqlalchemy-statement", 'def run(conn, user):\n    conn.execute(statement=text(f"SELECT * FROM users WHERE name = {user}"))\n', ((CRITICAL, 2),)),
    ("sqlalchemy-scalar", 'def run(conn, user):\n    conn.scalar(statement=text(f"SELECT {user}"))\n', ((CRITICAL, 2),)),
    ("sqlalchemy-scalars", 'def run(conn, user):\n    conn.scalars(statement=text(f"SELECT {user}"))\n', ((CRITICAL, 2),)),
    ("driver-sql-keyword", 'def run(conn, user):\n    conn.exec_driver_sql(statement=f"SELECT {user}")\n', ((CRITICAL, 2),)),
    ("driver-sql-positional", 'def run(conn, user):\n    conn.exec_driver_sql(f"SELECT {user}")\n', ((CRITICAL, 2),)),
    ("pandas-sql", 'def run(pd, conn, user):\n    pd.read_sql(con=conn, sql=f"SELECT {user}")\n', ((CRITICAL, 2),)),
    ("pandas-query", 'def run(pd, conn, user):\n    pd.read_sql_query(con=conn, sql="SELECT {}".format(user))\n', ((CRITICAL, 2),)),
    ("django-raw", 'def run(qs, user):\n    qs.raw(raw_query="SELECT %s" % user)\n', ((CRITICAL, 2),)),
    ("where-fstring", 'def run(qs, user):\n    qs.extra(where=[f"name = {user}"])\n', ((CRITICAL, 2),)),
    ("where-format", 'def run(qs, user):\n    qs.extra(where=["name = {}".format(user)])\n', ((CRITICAL, 2),)),
    ("where-percent", 'def run(qs, user):\n    qs.extra(where=["name = %s" % user])\n', ((CRITICAL, 2),)),
    ("where-concat", 'def run(qs, user):\n    qs.extra(where=["name = " + user])\n', ((CRITICAL, 2),)),
    ("where-positional", 'def run(qs, user):\n    qs.extra(None, [f"name = {user}"])\n', ((CRITICAL, 2),)),
    ("select-expression", 'def run(qs, user):\n    qs.extra(select={"flag": f"name = {user}"})\n', ((CRITICAL, 2),)),
    ("select-positional", 'def run(qs, user):\n    qs.extra({"flag": f"name = {user}"})\n', ((CRITICAL, 2),)),
    ("multiple-fragments-one-hit", 'def run(qs, user):\n    qs.extra(select={"flag": f"name = {user}"}, where=[f"id = {user}"])\n', ((CRITICAL, 2),)),
    ("fragment-warning", 'from settings import TABLE_VALUE\nqs.extra(where=[f"name = {TABLE_VALUE}"])\n', ((WARNING, 2),)),
    ("fragment-critical-wins", 'def run(qs, user):\n    qs.extra(select={"flag": f"id = {UNKNOWN}"}, where=[f"name = {user}"])\n', ((CRITICAL, 2),)),
    ("ordinary-positional", 'def run(cursor, user):\n    cursor.execute(f"SELECT {user}")\n', ((CRITICAL, 2),)),
    ("keyword-alias", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    cursor.execute(query=query)\n', ((CRITICAL, 3),)),
    ("multiline", 'def run(cursor, user):\n    cursor.execute(\n        query=f"SELECT {user}"\n    )\n', ((CRITICAL, 2),)),
    ("bound-query", 'def run(cursor, user):\n    cursor.execute(query="SELECT * FROM users WHERE name = %s", params=(user,))\n', ()),
    ("bound-sql-looking-data", 'def run(cursor, user):\n    cursor.execute(query="SELECT %s", params=(f"SELECT {user}",))\n', ()),
    ("bound-where", 'def run(qs, user):\n    qs.extra(where=["name = %s"], params=[f"SELECT {user}"])\n', ()),
    ("bound-select", 'def run(qs, user):\n    qs.extra(select={"flag": "name = %s"}, select_params=[f"SELECT {user}"])\n', ()),
    ("positional-bound-where", 'def run(qs, user):\n    qs.extra(None, ["name = %s"], [f"SELECT {user}"])\n', ()),
    ("bound-pandas", 'def run(pd, conn, user):\n    pd.read_sql(sql="SELECT ?", con=conn, params=[f"SELECT {user}"])\n', ()),
    ("bound-driver", 'def run(conn, user):\n    conn.exec_driver_sql(statement="SELECT ?", parameters=[f"SELECT {user}"])\n', ()),
    ("safe-select-alias", 'def run(qs, user):\n    qs.extra(select={f"label_{user}": "1"})\n', ()),
    ("static-fragment", 'qs.extra(where=[f"id = {7}"])\n', ()),
    ("unrelated-keyword", 'def run(cursor, user):\n    cursor.execute(metadata=f"SELECT {user}")\n', ()),
    ("non-sql-keyword", 'def run(cursor, user):\n    cursor.execute(query=f"hello {user}")\n', ()),
    ("ignored", 'def run(qs, user):\n    # ubs:ignore\n    qs.extra(where=[f"name = {user}"])\n', ()),
    ("branch-unsafe-first", 'def run(cursor, user, flag):\n    if flag:\n        query = f"SELECT {user}"\n    else:\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 6),)),
    ("branch-unsafe-last", 'def run(cursor, user, flag):\n    if flag:\n        query = "SELECT 1"\n    else:\n        query = f"SELECT {user}"\n    cursor.execute(query)\n', ((CRITICAL, 6),)),
    ("branch-implicit-bypass", 'def run(cursor, user, flag):\n    query = f"SELECT {user}"\n    if flag:\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 5),)),
    ("branch-safe-sibling-sink", 'def run(cursor, user, flag):\n    query = "SELECT 1"\n    if flag:\n        query = f"SELECT {user}"\n    else:\n        cursor.execute(query)\n', ()),
    ("branch-unsafe-sibling-sink", 'def run(cursor, user, flag):\n    query = f"SELECT {user}"\n    if flag:\n        query = "SELECT 1"\n    else:\n        cursor.execute(query)\n', ((CRITICAL, 6),)),
    ("branch-warning-first", 'def run(cursor, flag):\n    if flag:\n        query = f"SELECT {UNKNOWN}"\n    else:\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((WARNING, 6),)),
    ("branch-critical-over-warning", 'def run(cursor, user, flag):\n    if flag:\n        query = f"SELECT {user}"\n    else:\n        query = f"SELECT {UNKNOWN}"\n    cursor.execute(query)\n', ((CRITICAL, 6),)),
    ("branch-warning-over-critical", 'def run(cursor, user, flag):\n    if flag:\n        query = f"SELECT {UNKNOWN}"\n    else:\n        query = f"SELECT {user}"\n    cursor.execute(query)\n', ((CRITICAL, 6),)),
    ("branch-both-clean", 'def run(cursor, user, flag):\n    query = f"SELECT {user}"\n    if flag:\n        query = "SELECT 1"\n    else:\n        query = "SELECT 2"\n    cursor.execute(query)\n', ()),
    ("branch-later-overwrite", 'def run(cursor, user, flag):\n    if flag:\n        query = f"SELECT {user}"\n    else:\n        query = "SELECT 1"\n    query = "SELECT 2"\n    cursor.execute(query)\n', ()),
    ("branch-alias-retained", 'def run(cursor, user, flag):\n    if flag:\n        query = f"SELECT {user}"\n    else:\n        query = "SELECT 1"\n    saved = query\n    query = "SELECT 2"\n    cursor.execute(saved)\n', ((CRITICAL, 8),)),
    ("branch-bound-data", 'def run(cursor, user, flag):\n    if flag:\n        query = f"SELECT {user}"\n    else:\n        query = "SELECT 1"\n    cursor.execute("SELECT %s", (query,))\n', ()),
    ("nested-branches", 'def run(cursor, user, first, second):\n    query = "SELECT 1"\n    if first:\n        if second:\n            query = f"SELECT {user}"\n        else:\n            query = "SELECT 2"\n    cursor.execute(query)\n', ((CRITICAL, 8),)),
    ("nested-function-keeps-outer-query", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    def unused():\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 5),)),
    ("nested-function-does-not-taint-outer-query", 'def run(cursor, user):\n    query = "SELECT 1"\n    def unused():\n        query = f"SELECT {user}"\n    cursor.execute(query)\n', ()),
    ("sibling-function-does-not-taint-module", 'query = "SELECT 1"\ndef unrelated(user):\n    query = f"SELECT {user}"\ncursor.execute(query)\n', ()),
    ("local-parameter-masks-outer-query", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    def nested(query):\n        cursor.execute(query)\n', ()),
    ("closure-captures-query", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    def nested():\n        cursor.execute(query)\n', ((CRITICAL, 4),)),
    ("async-scope-restores-outer-query", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    async def unused():\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 5),)),
    ("function-default-evaluated-in-outer-scope", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    def nested(query=cursor.execute(query)):\n        return query\n', ((CRITICAL, 3),)),
    ("for-zero-iterations", 'def run(cursor, user, rows):\n    query = f"SELECT {user}"\n    for row in rows:\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 5),)),
    ("while-zero-iterations", 'def run(cursor, user, flag):\n    query = f"SELECT {user}"\n    while flag:\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 5),)),
    ("loop-carried-query", 'def run(cursor, user, rows):\n    query = "SELECT 1"\n    for row in rows:\n        cursor.execute(query)\n        query = f"SELECT {user}"\n', ((CRITICAL, 4),)),
    ("loop-carried-chain", 'def run(cursor, user, rows):\n    a = b = c = "SELECT 1"\n    for row in rows:\n        cursor.execute(a)\n        a = b\n        b = c\n        c = f"SELECT {user}"\n', ((CRITICAL, 4),)),
    ("loop-clean-overwrite-before-sink", 'def run(cursor, user, rows):\n    query = f"SELECT {user}"\n    for row in rows:\n        query = "SELECT 1"\n        cursor.execute(query)\n', ()),
    ("loop-break-bypasses-else", 'def run(cursor, user, rows):\n    query = f"SELECT {user}"\n    for row in rows:\n        break\n    else:\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 7),)),
    ("loop-else-cleans-normal-exit", 'def run(cursor, user, rows):\n    query = f"SELECT {user}"\n    for row in rows:\n        pass\n    else:\n        query = "SELECT 1"\n    cursor.execute(query)\n', ()),
    ("continue-bypasses-cleanup", 'def run(cursor, user, rows):\n    query = "SELECT 1"\n    for row in rows:\n        query = f"SELECT {user}"\n        continue\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 7),)),
    ("break-makes-following-sink-unreachable", 'def run(cursor, user, rows):\n    for row in rows:\n        break\n        cursor.execute(f"SELECT {user}")\n', ()),
    ("return-makes-following-sink-unreachable", 'def run(cursor, user):\n    return\n    cursor.execute(f"SELECT {user}")\n', ()),
    ("branch-return-does-not-clean-survivor", 'def run(cursor, user, flag):\n    query = f"SELECT {user}"\n    if flag:\n        return\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 6),)),
    ("both-branches-return", 'def run(cursor, user, flag):\n    if flag:\n        return\n    else:\n        return\n    cursor.execute(f"SELECT {user}")\n', ()),
    ("constant-false-while", 'def run(cursor, user):\n    while False:\n        cursor.execute(f"SELECT {user}")\n', ()),
    ("constant-true-while-without-exit", 'def run(cursor, user):\n    while True:\n        pass\n    cursor.execute(f"SELECT {user}")\n', ()),
    ("constant-true-loop-break", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    while True:\n        break\n    cursor.execute(query)\n', ((CRITICAL, 5),)),
    ("stable-loop-deduplicates-sink", 'def run(cursor, user, rows):\n    query = f"SELECT {user}"\n    for row in rows:\n        cursor.execute(query)\n', ((CRITICAL, 4),)),
    ("loop-promotes-warning-once", 'def run(cursor, user, rows):\n    query = f"SELECT {UNKNOWN}"\n    for row in rows:\n        cursor.execute(query)\n        query = f"SELECT {user}"\n', ((CRITICAL, 4),)),
    ("for-target-shadows-old-query", 'def run(cursor, user, rows):\n    query = f"SELECT {user}"\n    for query in ["SELECT 1"]:\n        cursor.execute(query)\n', ()),
    ("for-iterable-captures-query-value", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    for saved in [query]:\n        query = "SELECT 1"\n        cursor.execute(saved)\n', ((CRITICAL, 5),)),
    ("nested-loop-break-does-not-break-outer", 'def run(cursor, user, rows):\n    query = "SELECT 1"\n    for row in rows:\n        while True:\n            break\n        query = f"SELECT {user}"\n    cursor.execute(query)\n', ((CRITICAL, 7),)),
    ("async-for-carried-query", 'async def run(cursor, user, rows):\n    query = "SELECT 1"\n    async for row in rows:\n        cursor.execute(query)\n        query = f"SELECT {user}"\n', ((CRITICAL, 4),)),
    ("assignment-rhs-observes-old-query", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    query = cursor.execute(query)\n', ((CRITICAL, 3),)),
    ("annotated-rhs-observes-old-query", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    query: object = cursor.execute(query)\n', ((CRITICAL, 3),)),
    ("named-expression-stores-query", 'def run(cursor, user):\n    if (query := f"SELECT {user}"):\n        cursor.execute(query)\n', ((CRITICAL, 3),)),
    ("named-expression-kills-query", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    if (query := "SELECT 1"):\n        cursor.execute(query)\n', ()),
    ("loop-bound-values-stay-data", 'def run(cursor, user, rows):\n    query = "SELECT 1"\n    for row in rows:\n        cursor.execute("SELECT %s", (query,))\n        query = f"SELECT {user}"\n', ()),
)


class SQLSinkArguments(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        artifacts = ROOT / "test-suite" / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        cls.artifacts = Path(tempfile.mkdtemp(prefix="python-sql-arguments-", dir=artifacts))
        cls.detector_hash = hashlib.sha256(Path(detector.__file__).read_bytes()).hexdigest()

    def test_independently_labelled_programs(self):
        for name, source, expected in CASES:
            with self.subTest(case=name):
                path = self.artifacts / (name + ".py")
                path.write_text(textwrap.dedent(source), encoding="utf-8")
                previous = os.environ.pop(detector.SANITIZER_ENV, None)
                started = time.perf_counter()
                try:
                    findings = list(detector.find([path]))
                finally:
                    if previous is not None:
                        os.environ[detector.SANITIZER_ENV] = previous
                actual = tuple(sorted((rule, line) for rule, _, line, _, _ in findings))
                record = {
                    "case": name,
                    "command": "sql_injection.find([source])",
                    "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "detector_sha256": self.detector_hash,
                    "python": sys.version,
                    "elapsed_seconds": time.perf_counter() - started,
                    "expected": expected,
                    "actual": actual,
                    "passed": actual == tuple(sorted(expected)),
                }
                path.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
                self.assertEqual(actual, tuple(sorted(expected)), source)
                for _, found_path, _, column, _ in findings:
                    self.assertEqual(found_path, path)
                    self.assertEqual(column, 1)

    def test_fixed_point_budget_is_not_a_clean_result(self):
        source = 'def run(cursor, user, rows):\n    for row in rows:\n        cursor.execute(f"SELECT {user}")\n'
        tree = ast.parse(source)
        params, risks = detector.build_provenance(tree)
        analyzer = detector.SQLInjectionAnalyzer(source, source.splitlines(), params, risks, max_steps=1)
        with self.assertRaisesRegex(RuntimeError, 'budget.*incomplete'):
            analyzer.visit(tree)


if __name__ == "__main__":
    unittest.main(verbosity=2)
