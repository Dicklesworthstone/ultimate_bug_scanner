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


if __name__ == "__main__":
    unittest.main(verbosity=2)
