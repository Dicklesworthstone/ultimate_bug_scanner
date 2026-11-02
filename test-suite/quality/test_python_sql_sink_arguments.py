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
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "modules" / "helpers"))
from ubs_core.py_detectors import sql_injection as detector

CRITICAL = "py.security.sql-injection"
WARNING = "py.security.sql-injection-unproven"

NESTED_LOOP_BUILDER = (
    'def inner(value):\n'
    '    query = "SELECT 1"\n'
    '    for item in (value,):\n'
    '        query = f"SELECT {item}"\n'
    '    return query\n'
    'def outer(value):\n'
    '    return inner(value)\n'
)

RAW_PROCESS_WRAPPER = textwrap.dedent('''\
    import subprocess
    def wrap(run):
        return run
    def check(repo):
        calls = []
        def raw(*args):
            calls.append(args)
            return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, timeout=10, check=True)
        reads = [("rev-parse", "HEAD"), ("log", "-1")]
        cached = wrap(raw)
        before = [cached(*args).stdout for args in reads]
        calls.clear()
        assert not any(args in reads for args in calls)
        expected = [raw(*args) for args in reads]
        assert before == [result.stdout for result in expected]
''')

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
    ("fromkeys-mixed-primitives", 'def run(cursor, user):\n    keys = dict.fromkeys(key for key in ("entry", 1, None))\n    cursor.execute("SELECT ?", (user,))\n', ()),
    ("fromkeys-tuple-default", 'def run(cursor, user):\n    queries = dict.fromkeys(((name, index) for name, index in [("users", 1)]), f"SELECT {user}")\n    cursor.execute(queries[("users", 1)])\n', ((CRITICAL, 3),)),
    ("fromkeys-tuple-bound", 'def run(cursor, user):\n    queries = dict.fromkeys(((name, index) for name, index in [("users", 1)]), "SELECT ?")\n    cursor.execute(queries[("users", 1)], (user,))\n', ()),
    ("fromkeys-nested-tuple", 'def run(cursor, user):\n    keys = dict.fromkeys(key for key in ((("users", 1), None),))\n    cursor.execute(f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("application-method-fields", 'class Runner:\n    def __init__(self):\n        self.count = 0\n    def execute(self, query):\n        self.count += 1\n        return len(query) + self.count\n    def run(self, user):\n        return self.execute(f"SELECT {user}")\n', ()),
    ("application-method-field-sql", 'from backend import run_query\nclass Runner:\n    def execute(self, query):\n        self.saved = query\n        return run_query(self.saved)\n    def run(self, user):\n        return self.execute(f"SELECT {user}")\n', ((CRITICAL, 7),)),
    ("local-raw-process-wrapper", RAW_PROCESS_WRAPPER, ()),
    ("local-raw-opaque-sql", 'from backend import dispatch\ndef raw(*args):\n    return dispatch(*args)\ndef run(user):\n    raw(f"SELECT {user}")\n', ((CRITICAL, 5),)),
    ("imported-sql-alias-positional", 'from pandas import read_sql as load_rows\ndef run(conn, user):\n    return load_rows(f"SELECT {user}", conn)\n', ((CRITICAL, 3),)),
    ("imported-sql-alias-keyword", 'from pandas import read_sql as load_rows\ndef run(conn, user):\n    return load_rows(con=conn, sql=f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("imported-sql-alias-bound-data", 'from pandas import read_sql as load_rows\ndef run(conn, user):\n    return load_rows("SELECT ?", conn, params=(f"SELECT {user}",))\n', ()),
    ("imported-sql-alias-unproven", 'from pandas import read_sql as load_rows\nfrom settings import TABLE_NAME\nload_rows(f"SELECT * FROM {TABLE_NAME}", conn)\n', ((WARNING, 3),)),
    ("imported-sql-alias-local-copy", 'from pandas import read_sql as load_rows\ndef run(conn, user):\n    fetch = load_rows\n    return fetch(sql=f"SELECT {user}", con=conn)\n', ((CRITICAL, 4),)),
    ("imported-sql-alias-parameter-shadow", 'from pandas import read_sql as load_rows\ndef format_note(load_rows, user):\n    return load_rows(f"SELECT {user}")\n', ()),
    ("application-sql-builder-length", 'def make(value):\n    return f"SELECT {value}"\ndef execute(value):\n    return len(make(value))\ndef run(user):\n    return execute(user)\n', ()),
    ("nested-sql-builder-length", NESTED_LOOP_BUILDER + 'def raw(value):\n    return len(outer(value))\ndef run(user):\n    return raw(user)\n', ()),
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
    ("except-does-not-overwrite-normal-path", 'def run(cursor, user):\n    try:\n        query = f"SELECT {user}"\n    except ValueError:\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 6),)),
    ("exception-before-literal-overwrite", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        work()\n        query = "SELECT 1"\n    except Exception:\n        pass\n    cursor.execute(query)\n', ((CRITICAL, 8),)),
    ("unreachable-handler-stays-clean", 'def run(cursor, user):\n    query = "SELECT 1"\n    try:\n        query = "SELECT 2"\n    except Exception:\n        query = f"SELECT {user}"\n    cursor.execute(query)\n', ()),
    ("exception-after-literal-overwrite", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        query = "SELECT 1"\n        work()\n    except Exception:\n        cursor.execute(query)\n', ()),
    ("failed-rhs-keeps-old-query", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        query = get_constant_query()\n    except Exception:\n        cursor.execute(query)\n', ((CRITICAL, 6),)),
    ("failed-format-does-not-store-new-query", 'def run(cursor, user):\n    query = "SELECT 1"\n    try:\n        query = f"SELECT {user}"\n    except Exception:\n        cursor.execute(query)\n', ()),
    ("finally-runs-on-return", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        return\n        query = "SELECT 1"\n    finally:\n        cursor.execute(query)\n', ((CRITICAL, 7),)),
    ("finally-return-makes-successor-unreachable", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        work()\n    finally:\n        return\n    cursor.execute(query)\n', ()),
    ("finally-cleans-break-exit", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    while True:\n        try:\n            break\n        finally:\n            query = "SELECT 1"\n    cursor.execute(query)\n', ()),
    ("finally-preserves-unsafe-break", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    while True:\n        try:\n            break\n        finally:\n            if flag:\n                query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 9),)),
    ("finally-raise-makes-successor-unreachable", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        pass\n    finally:\n        raise RuntimeError()\n    cursor.execute(query)\n', ()),
    ("finally-continue-replaces-break", 'def run(cursor, user):\n    while True:\n        try:\n            break\n        finally:\n            continue\n    cursor.execute(f"SELECT {user}")\n', ()),
    ("except-bare-raise-preserves-outer-state", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        try:\n            work()\n        except Exception:\n            raise\n            query = "SELECT 1"\n    except Exception:\n        cursor.execute(query)\n', ((CRITICAL, 10),)),
    ("try-else-only-normal-path", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        work()\n    except Exception:\n        pass\n    else:\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 9),)),
    ("except-does-not-run-after-return", 'def run(cursor, user):\n    try:\n        return\n    except Exception:\n        cursor.execute(f"SELECT {user}")\n', ()),
    ("explicit-raise-bypasses-following-cleanup", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        raise ValueError()\n        query = "SELECT 1"\n    except Exception:\n        cursor.execute(query)\n', ((CRITICAL, 7),)),
    ("with-propagates-return", 'def run(cursor, user, manager):\n    with manager:\n        return\n    cursor.execute(f"SELECT {user}")\n', ()),
    ("with-may-suppress-exception", 'def run(cursor, user, manager):\n    query = f"SELECT {user}"\n    with manager:\n        work()\n        query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 6),)),
    ("async-with-propagates-return", 'async def run(cursor, user, manager):\n    async with manager:\n        return\n    cursor.execute(f"SELECT {user}")\n', ()),
    ("with-target-masks-old-query", 'def run(cursor, user, manager):\n    query = f"SELECT {user}"\n    with manager as query:\n        cursor.execute(query)\n', ()),
    ("class-local-does-not-clear-module-query", 'query = f"SELECT {source()}"\nclass Holder:\n    query = "SELECT 1"\ncursor.execute(query)\n', ((CRITICAL, 4),)),
    ("class-local-does-not-taint-module-query", 'query = "SELECT 1"\nclass Holder:\n    query = f"SELECT {source()}"\ncursor.execute(query)\n', ()),
    ("uncalled-lambda-does-not-clear-query", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    callback = lambda: (query := "SELECT 1")\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ("exception-from-subscript", 'def run(cursor, user, values):\n    query = f"SELECT {user}"\n    try:\n        item = values[0]\n        query = "SELECT 1"\n    except Exception:\n        cursor.execute(query)\n', ((CRITICAL, 7),)),
    ("exception-from-attribute", 'def run(cursor, user, value):\n    query = f"SELECT {user}"\n    try:\n        item = value.attribute\n        query = "SELECT 1"\n    except Exception:\n        cursor.execute(query)\n', ((CRITICAL, 7),)),
    ("exception-from-arithmetic", 'def run(cursor, user, value):\n    query = f"SELECT {user}"\n    try:\n        item = 1 / value\n        query = "SELECT 1"\n    except Exception:\n        cursor.execute(query)\n', ((CRITICAL, 7),)),
    ("exception-from-await", 'async def run(cursor, user, task):\n    query = f"SELECT {user}"\n    try:\n        item = await task\n        query = "SELECT 1"\n    except Exception:\n        cursor.execute(query)\n', ((CRITICAL, 7),)),
    ("short-circuit-and-preserves-bypass", 'def run(cursor, user, flag):\n    query = f"SELECT {user}"\n    flag and (query := "SELECT 1")\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ("short-circuit-or-preserves-bypass", 'def run(cursor, user, flag):\n    query = f"SELECT {user}"\n    flag or (query := "SELECT 1")\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ("constant-short-circuit-skips-sink", 'def run(cursor, user):\n    False and cursor.execute(f"SELECT {user}")\n', ()),
    ("conditional-expression-joins-writes", 'def run(cursor, user, flag):\n    query = "SELECT 1"\n    (query := f"SELECT {user}") if flag else (query := "SELECT 2")\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ("finally-deduplicates-normal-and-raise", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        work()\n    finally:\n        cursor.execute(query)\n', ((CRITICAL, 6),)),
    ("assert-failure-reaches-handler-before-cleanup", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        assert False\n        query = "SELECT 1"\n    except AssertionError:\n        cursor.execute(query)\n', ((CRITICAL, 7),)),
    ("handler-type-failure-still-runs-finally", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        work()\n    except make_exception_type():\n        return\n    except:\n        return\n    finally:\n        cursor.execute(query)\n', ((CRITICAL, 10),)),
    ("optimized-assert-does-not-hide-sink", 'def run(cursor, user):\n    assert False\n    cursor.execute(f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("optimized-assert-does-not-prove-cleanup", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    assert (query := "SELECT 1")\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ("empty-literal-loop-has-no-body-effects", 'def run(cursor, user):\n    for item in []:\n        cursor.execute(f"SELECT {user}")\n', ()),
    ("singleton-loop-does-not-invent-backedge", 'def run(cursor, user):\n    query = "SELECT 1"\n    for item in [1]:\n        cursor.execute(query)\n        query = f"SELECT {user}"\n', ()),
    ("two-element-loop-has-real-backedge", 'def run(cursor, user):\n    query = "SELECT 1"\n    for item in (1, 2):\n        cursor.execute(query)\n        query = f"SELECT {user}"\n', ((CRITICAL, 4),)),
    ("literal-iterable-values-captured-before-body", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    for saved in [query, "SELECT 1"]:\n        query = "SELECT 1"\n        cursor.execute(saved)\n', ((CRITICAL, 5),)),
    ("constant-format-does-not-enter-handler", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        query = f"SELECT {7}"\n    except:\n        cursor.execute(query)\n', ()),
    ("simple-class-does-not-enter-handler", 'def run(cursor, user):\n    query = f"SELECT {user}"\n    try:\n        class Marker:\n            pass\n    except:\n        cursor.execute(query)\n', ()),
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

    def test_literal_statements_do_not_depend_on_unrelated_closure_ownership(self):
        # A closure may need heap analysis, but cannot change a string literal
        # in a separate SQL call. Keep the closure present, not suppressed.
        unrelated = ('class Worker:\n'
                     '    def collect(self, value):\n'
                     '        events = []\n'
                     '        def record(item):\n'
                     '            events.append(item)\n'
                     '            raise ValueError(item)\n'
                     '        record(value)\n')
        for name, statement in (
                ('positional', 'cursor.execute("SELECT ?", (user,))'),
                ('keyword', 'cursor.execute(query="SELECT ?", params=(user,))'),
                ('import-alias', 'fetch("SELECT ?", conn, params=(user,))')):
            with self.subTest(case=name):
                path = self.artifacts / ('literal-closure-' + name + '.py')
                path.write_text('from pandas import read_sql as fetch\n' + unrelated
                                + 'def run(cursor, conn, user):\n    ' + statement + '\n',
                                encoding='utf-8')
                self.assertEqual(list(detector.find([path])), [])

    def test_core_tests_literal_sql_fits_the_original_budget(self):
        # This real source triggered the failure: fixed SQLite statements in
        # one method caused every unrelated test body to consume SQL flow.
        self.assertEqual(list(detector.find([Path(__file__).with_name('test_ubs_core.py')])), [])

    def test_literal_scope_admission_keeps_decorators_and_reflection(self):
        closure = ('events = []\n'
                   'def record(item):\n    events.append(item)\n    raise ValueError(item)\n'
                   'record(value)\n')
        worker = 'class Worker:\n    def collect(self):\n' + textwrap.indent(closure, '        ')
        cases = (
            ('decorated-function', 'def invoke(fn):\n    fn()\n    return fn\n'
             '@invoke\ndef hidden():\n' + textwrap.indent(closure, '    ')),
            ('decorated-method', 'def invoke(fn):\n    fn()\n    return fn\n'
             'class Worker:\n    @invoke\n    def collect():\n' + textwrap.indent(closure, '        ')),
            ('aliased-attrgetter', 'from operator import attrgetter as grab\n' + worker
             + 'callback = grab("col" + "lect")(Worker())\ncallback()\n'),
            ('aliased-methodcaller', 'from operator import methodcaller as call\n' + worker
             + 'call("col" + "lect")(Worker())\n'),
            ('attribute-protocol', worker + 'Worker().__getattribute__("col" + "lect")()\n'),
            ('literal-getattr', worker + 'getattr(Worker(), "collect")()\n'),
            ('aliased-getattr', worker + 'grab = getattr\ngrab(Worker(), "col" + "lect")()\n'),
            ('literal-namespace', worker + 'getattr(Worker, "__dict__")["col" + "lect"](Worker())\n'),
            ('literal-reflective-method', worker
             + 'getattr(Worker(), "__getattribute__")("col" + "lect")()\n'),
            ('expanded-selector', worker
             + 'getattr(*(Worker, "__dict__"), "unused")["col" + "lect"](Worker())\n'),
        )
        for name, source in cases:
            with self.subTest(case=name):
                path = self.artifacts / ('literal-sql-reachable-' + name + '.py')
                path.write_text('cursor.execute("SELECT 1")\n' + source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure list ownership'):
                    list(detector.find([path]))

    def test_literal_statements_do_not_hide_ambiguous_or_opaque_sql(self):
        for name, source, reason in (
                ('ambiguous', 'from backend import execute as fetch\n'
                 'if configured:\n    fetch = replacement\n'
                 'def run(user):\n    fetch("SELECT ?", (f"SELECT {user}",))\n',
                 'aliased execution binding'),
                ('facade', 'from backend import dispatch\n'
                 'def raw(value):\n    dispatch(f"SELECT {value}")\n'
                 'def run(user):\n    raw(user)\n', 'facade forwarding call'),
                ('same-scope-closure', 'def run(cursor, user):\n'
                 '    events = []\n'
                 '    def record(item):\n        events.append(item)\n        raise ValueError(item)\n'
                 '    record(user)\n    cursor.execute("SELECT ?", (user,))\n',
                 'closure list ownership')):
            with self.subTest(case=name):
                path = self.artifacts / ('literal-sql-negative-' + name + '.py')
                path.write_text('cursor.execute("SELECT 1")\n' + source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, reason):
                    list(detector.find([path]))

    @unittest.skipIf(sys.version_info < (3, 11), 'except* syntax requires Python 3.11')
    def test_exception_groups_are_explicitly_incomplete(self):
        path = self.artifacts / 'exception_group.py'
        path.write_text('try:\n    cursor.execute(f"SELECT {user}")\nexcept* ValueError:\n    recover()\n', encoding='utf-8')
        with self.assertRaisesRegex(RuntimeError, r'except\*.*incomplete'):
            list(detector.find([path]))


@unittest.skipUnless((ROOT / 'ubs').is_file() and (ROOT / 'modules/ubs-python.sh').is_file(),
                     'real CLI requires a full source checkout')
class SQLSinkArgumentsCLI(unittest.TestCase):
    def test_real_cli_unresolved_sql_execution_is_partial(self):
        artifacts = ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        run = Path(tempfile.mkdtemp(prefix='python-sql-alias-partial-', dir=artifacts))
        cases = (
            ('ambiguous-query', 'from pandas import read_sql as fetch\n'
             'if configured:\n    fetch = replacement\n'
             'def run(conn, user):\n    return fetch(f"SELECT {user}", conn)\n', [], 'aliased execution binding'),
            ('ambiguous-second-argument', 'from backend import execute as fetch\n'
             'if configured:\n    fetch = replacement\n'
             'def run(user):\n    return fetch("SELECT ?", (f"SELECT {user}",))\n', [], 'aliased execution binding'),
            ('retained-before-ambiguity', 'from backend import execute as fetch\n'
             'def run(cursor, user):\n    cursor.execute(f"SELECT {user}")\n'
             '    fetch(f"SELECT {user}")\n'
             'if configured:\n    fetch = replacement\n', [3], 'aliased execution binding'),
            ('opaque-internal-query', 'from backend import dispatch\n'
             'def raw(value):\n    return dispatch(f"SELECT {value}")\n'
             'def run(user):\n    return raw(user)\n', [], 'facade forwarding call'),
            ('opaque-builder-return', 'from backend import dispatch\n'
             'def make(value):\n    return f"SELECT {value}"\n'
             'def raw(value):\n    return dispatch(make(value))\n'
             'def run(user):\n    return raw(user)\n', [], 'facade forwarding call'),
            ('opaque-nested-loop-return', 'from backend import dispatch\n' + NESTED_LOOP_BUILDER
             + 'def raw(value):\n    return dispatch(outer(value))\n'
             'def run(user):\n    return raw(user)\n', [], 'facade forwarding call'),
            ('opaque-captured-template', 'from backend import dispatch\nTEMPLATE = "SELECT {}"\n'
             'def raw(value):\n    return dispatch(TEMPLATE.format(value))\n'
             'def run(user):\n    return raw(user)\n', [], 'facade forwarding call'),
            ('opaque-heap-store', 'from backend import dispatch, record\n'
             'def execute(value):\n    record.query = f"SELECT {value}"\n'
             '    return dispatch(record.query)\n'
             'def run(user):\n    return execute(user)\n', [], 'facade heap or closure store'),
            ('retained-before-opaque-forward', 'from backend import dispatch\n'
             'def raw(cursor, value):\n    cursor.execute(f"SELECT {value}")\n'
             '    return dispatch(f"SELECT {value}")\n'
             'def run(cursor, user):\n    return raw(cursor, user)\n', [3], 'facade forwarding call'),
        )
        detector_hash = hashlib.sha256(Path(detector.__file__).read_bytes()).hexdigest()
        for name, source, expected_lines, expected_error in cases:
            for entry in ('module', 'runner'):
                for fmt in ('json', 'sarif'):
                    with self.subTest(case=name, entry=entry, format=fmt):
                        folder = run / f'{name}-{entry}-{fmt}'
                        folder.mkdir()
                        path = folder / 'case.py'
                        path.write_text(source, encoding='utf-8')
                        for child in ('tmp', 'cache', 'data'):
                            (folder / child).mkdir()
                        env = {key: value for key, value in os.environ.items()
                               if not key.startswith('UBS_')}
                        env.update(TMPDIR=str(folder / 'tmp'), XDG_CACHE_HOME=str(folder / 'cache'),
                                   XDG_DATA_HOME=str(folder / 'data'), NO_COLOR='1',
                                   PYTHONDONTWRITEBYTECODE='1', UBS_NO_AUTO_UPDATE='1',
                                   UBS_KEEP_TEMP='1', ENABLE_UV_TOOLS='0')
                        executable = ROOT / ('ubs' if entry == 'runner' else 'modules/ubs-python.sh')
                        command = ['bash', str(executable), '--ci', '--no-color', '--format=' + fmt,
                                   '--skip=' + ','.join(str(n) for n in range(1, 24) if n != 7),
                                   '--only=python' if entry == 'runner' else '--no-uv', str(path)]
                        started = time.perf_counter()
                        try:
                            result = subprocess.run(command, cwd=folder, env=env, capture_output=True,
                                                    text=True, timeout=120, check=False)
                        except subprocess.TimeoutExpired as exc:
                            (folder / 'stdout.log').write_bytes(exc.stdout or b'')
                            (folder / 'stderr.log').write_bytes(exc.stderr or b'')
                            self.fail(f'CLI timeout; complete evidence: {folder}')
                        (folder / 'stdout.log').write_text(result.stdout, encoding='utf-8')
                        (folder / 'stderr.log').write_text(result.stderr, encoding='utf-8')
                        (folder / 'run.json').write_text(json.dumps({
                            'command': command, 'returncode': result.returncode,
                            'detector_sha256': detector_hash,
                            'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                            'elapsed_seconds': time.perf_counter() - started,
                        }, indent=2) + '\n', encoding='utf-8')
                        self.assertEqual(result.returncode, 2, f'{folder}\n{result.stdout}\n{result.stderr}')
                        document = json.loads(result.stdout)
                        self.assertIn('SQLFlowLimit', result.stdout, folder)
                        self.assertIn(expected_error, result.stdout, folder)
                        if fmt == 'json':
                            self.assertEqual(document['status'], 'partial', folder)
                            scanners = document['scanners'] if entry == 'runner' else [document]
                            self.assertEqual(len(scanners), 1, folder)
                            self.assertEqual(scanners[0]['status'], 'partial', folder)
                            actual = [sample['line'] for group in scanners[0]['findings']
                                      if group.get('rule_id', group.get('rule')) == CRITICAL
                                      for sample in group['samples']]
                        else:
                            self.assertTrue(any(invocation.get('executionSuccessful') is False
                                                for scan in document['runs']
                                                for invocation in scan.get('invocations', [])), folder)
                            actual = [finding['locations'][0]['physicalLocation']['region']['startLine']
                                      for scan in document['runs'] for finding in scan.get('results', [])
                                      if finding['ruleId'] == CRITICAL]
                        self.assertEqual(actual, expected_lines, folder)

    def test_real_cli_json_and_sarif(self):
        artifacts = ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        run = Path(tempfile.mkdtemp(prefix='python-sql-flow-cli-', dir=artifacts))
        selected = {'loop-carried-query', 'loop-bound-values-stay-data',
                    'exception-before-literal-overwrite', 'finally-cleans-break-exit',
                    'fromkeys-mixed-primitives', 'fromkeys-tuple-default',
                    'fromkeys-tuple-bound', 'fromkeys-nested-tuple',
                    'application-method-fields', 'application-method-field-sql',
                    'application-sql-builder-length',
                    'nested-sql-builder-length',
                    'local-raw-process-wrapper', 'local-raw-opaque-sql',
                    'imported-sql-alias-positional', 'imported-sql-alias-keyword',
                    'imported-sql-alias-bound-data', 'imported-sql-alias-unproven',
                    'imported-sql-alias-local-copy', 'imported-sql-alias-parameter-shadow'}
        tools = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                 for name in ('ubs', 'modules/ubs-python.sh',
                              'modules/helpers/ubs_core/py_detectors/sql_injection.py')}
        for name, source, expected in CASES:
            if name not in selected:
                continue
            for entry in ('module', 'runner'):
                for format_name in ('json', 'sarif'):
                    with self.subTest(case=name, entry=entry, format=format_name):
                        folder = run / f'{name}-{entry}-{format_name}'
                        folder.mkdir()
                        path = folder / 'case.py'
                        path.write_text(source, encoding='utf-8')
                        for child in ('tmp', 'home', 'cache'):
                            (folder / child).mkdir()
                        env = {key: value for key, value in os.environ.items() if not key.startswith('UBS_')}
                        skip_categories = ','.join(str(n) for n in range(1, 24) if n != 7)
                        env.update(HOME=str(folder / 'home'), XDG_CACHE_HOME=str(folder / 'cache'),
                                   TMPDIR=str(folder / 'tmp'), NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1',
                                   UBS_NO_AUTO_UPDATE='1', UBS_KEEP_TEMP='1', ENABLE_UV_TOOLS='0',
                                   UBS_SKIP_CATEGORIES=skip_categories)
                        executable = ROOT / ('ubs' if entry == 'runner' else 'modules/ubs-python.sh')
                        command = ['bash', str(executable), '--ci', '--fail-on-warning', '--no-color', f'--format={format_name}',
                                   '--skip=' + skip_categories]
                        command += ['--only=python'] if entry == 'runner' else ['--no-uv']
                        command.append(str(path))
                        started = time.perf_counter()
                        try:
                            result = subprocess.run(command, cwd=folder, env=env, capture_output=True,
                                                    text=True, timeout=120, check=False)
                        except subprocess.TimeoutExpired as exc:
                            for stream in ('stdout', 'stderr'):
                                data = getattr(exc, stream) or b''
                                if isinstance(data, str):
                                    data = data.encode('utf-8')
                                (folder / f'{stream}.log').write_bytes(data)
                            (folder / 'run.json').write_text(json.dumps({
                                'command': command, 'status': 'timeout', 'tools': tools,
                                'elapsed_seconds': time.perf_counter() - started,
                            }, indent=2) + '\n', encoding='utf-8')
                            self.fail(f'CLI timeout; complete evidence: {folder}')
                        (folder / 'stdout.log').write_text(result.stdout, encoding='utf-8')
                        (folder / 'stderr.log').write_text(result.stderr, encoding='utf-8')
                        (folder / 'run.json').write_text(json.dumps({
                            'command': command, 'returncode': result.returncode, 'tools': tools,
                            'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                            'elapsed_seconds': time.perf_counter() - started, 'python': sys.version,
                            'environment': {key: env[key] for key in ('HOME', 'XDG_CACHE_HOME', 'TMPDIR',
                                            'UBS_NO_AUTO_UPDATE', 'UBS_KEEP_TEMP', 'UBS_SKIP_CATEGORIES',
                                            'ENABLE_UV_TOOLS')},
                        }, indent=2) + '\n', encoding='utf-8')
                        self.assertEqual(result.returncode, 1 if expected else 0,
                                         f'{folder}\n{result.stdout}\n{result.stderr}')
                        try:
                            document = json.loads(result.stdout)
                        except ValueError as exc:
                            self.fail(f'Malformed CLI JSON at {folder}: {exc}\n{result.stdout}')
                        actual = []
                        if format_name == 'json':
                            scanners = document['scanners'] if entry == 'runner' else [document]
                            self.assertEqual(len(scanners), 1, folder)
                            summary = scanners[0]
                            self.assertEqual(summary['status'], 'ok', folder)
                            self.assertEqual(summary['files'], 1, folder)
                            groups = summary['findings']
                            for severity in ('critical', 'warning', 'info'):
                                self.assertEqual(summary[severity], sum(group['count'] for group in groups
                                                 if group['severity'] == severity), folder)
                            for group in groups:
                                rule = group.get('rule_id', group.get('rule'))
                                if rule not in {CRITICAL, WARNING}:
                                    continue
                                self.assertEqual(group['count'], 1, folder)
                                self.assertEqual(len(group['samples']), 1, folder)
                                sample = group['samples'][0]
                                self.assertEqual(Path(sample['file']).name, path.name, folder)
                                actual.append((rule, sample['line']))
                        else:
                            self.assertEqual(document['version'], '2.1.0', folder)
                            for sarif_run in document['runs']:
                                for finding in sarif_run.get('results', []):
                                    if finding['ruleId'] not in {CRITICAL, WARNING}:
                                        continue
                                    location = finding['locations'][0]['physicalLocation']
                                    self.assertEqual(Path(unquote(location['artifactLocation']['uri'])).name,
                                                     path.name, folder)
                                    self.assertEqual(location['region']['startColumn'], 1, folder)
                                    actual.append((finding['ruleId'], location['region']['startLine']))
                        self.assertEqual(sorted(actual), sorted(expected), folder)


if __name__ == "__main__":
    unittest.main(verbosity=2)
