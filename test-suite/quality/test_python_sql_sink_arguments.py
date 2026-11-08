#!/usr/bin/env python3
"""Independent SQL argument-position and predicate regressions.

Run directly with Python, or through unittest discovery. Source fixtures are
parsed by UBS; a separate in-memory SQLite witness checks saved-callable and
parameter-binding semantics. Expected public IDs and locations come from API
argument semantics, not from another detector implementation.

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
import sqlite3
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

# A saved Python bound method captures its receiver and function at the point
# of attribute access. Later receiver/method/name assignments do not change
# an already saved callable. These labels follow that execution contract.
BOUND_SQL_CASES = (
    ("bound-execute-alias", 'def run(db, user):\n    submit = db.execute\n    submit(f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("bound-sqlite-alias", 'import sqlite3\ndef run(path, user):\n    db = sqlite3.connect(path)\n    submit = db.execute\n    submit(f"SELECT {user}")\n', ((CRITICAL, 5),)),
    ("bound-query-keyword", 'def run(db, user):\n    submit = db.execute\n    submit(query=f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("bound-statement-keyword", 'def run(db, user):\n    submit = db.execute\n    submit(statement=f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("bound-executemany", 'def run(db, user, rows):\n    submit = db.executemany\n    submit(query=f"INSERT INTO {user} VALUES (?)", params_seq=rows)\n', ((CRITICAL, 3),)),
    ("bound-executescript", 'def run(db, user):\n    submit = db.executescript\n    submit(f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("bound-driver-sql", 'def run(db, user):\n    submit = db.exec_driver_sql\n    submit(statement=f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("bound-raw-query", 'def run(manager, user):\n    submit = manager.raw\n    submit(raw_query=f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("bound-extra-predicate", 'def run(queryset, user):\n    extend = queryset.extra\n    extend(where=[f"name = {user}"])\n', ((CRITICAL, 3),)),
    ("bound-scalar", 'def run(db, user):\n    submit = db.scalar\n    submit(statement=f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("bound-scalars", 'def run(db, user):\n    submit = db.scalars\n    submit(statement=f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("bound-read-sql", 'import pandas as pd\ndef run(conn, user):\n    fetch = pd.read_sql\n    return fetch(con=conn, sql=f"SELECT {user}")\n', ((CRITICAL, 4),)),
    ("bound-read-sql-query", 'import pandas as pd\ndef run(conn, user):\n    fetch = pd.read_sql_query\n    return fetch(sql=f"SELECT {user}", con=conn)\n', ((CRITICAL, 4),)),
    ("bound-alias-chain", 'def run(db, user):\n    submit = db.execute\n    later = submit\n    later(f"SELECT {user}")\n', ((CRITICAL, 4),)),
    ("bound-chained-assignment", 'def run(db, user):\n    first = second = db.execute\n    second(f"SELECT {user}")\n', ((CRITICAL, 3),)),
    ("bound-receiver-reassigned", 'def run(db, user):\n    submit = db.execute\n    db = object()\n    submit(f"SELECT {user}")\n', ((CRITICAL, 4),)),
    ("bound-saved-before-replacement", 'def run(db, user):\n    submit = db.execute\n    saved = submit\n    submit = print\n    saved(f"SELECT {user}")\n', ((CRITICAL, 5),)),
    ("bound-method-replaced-after-capture", 'def run(db, user):\n    submit = db.execute\n    db.execute = print\n    submit(f"SELECT {user}")\n', ((CRITICAL, 4),)),
    ("bound-nested-capture", 'def run(db, user):\n    submit = db.execute\n    def invoke():\n        return submit(f"SELECT {user}")\n    return invoke()\n', ((CRITICAL, 4),)),
    ("bound-unproven-static", 'from settings import TABLE\ndef run(db):\n    submit = db.execute\n    submit(f"SELECT * FROM {TABLE}")\n', ((WARNING, 4),)),
    ("bound-parameterized", 'def run(db, user):\n    submit = db.execute\n    submit("SELECT ?", (user,))\n', ()),
    ("bound-keyword-parameterized", 'def run(db, user):\n    submit = db.execute\n    submit(query="SELECT %s", params=(user,))\n', ()),
    ("bound-alias-sql-looking-data", 'def run(db, user):\n    submit = db.execute\n    submit("SELECT ?", (f"SELECT {user}",))\n', ()),
    ("bound-known-slot-keyword-expansion", 'def run(db, options):\n    submit = db.execute\n    submit("SELECT ?", **options)\n', ()),
    ("bound-unused", 'def run(db, user):\n    submit = db.execute\n    query = f"SELECT {user}"\n    return len(query)\n', ()),
    ("bound-replaced-before-use", 'def run(db, user):\n    submit = db.execute\n    submit = print\n    submit(f"SELECT {user}")\n', ()),
    ("bound-safe-copy-before-sql-replacement", 'def run(db, user):\n    submit = print\n    saved = submit\n    submit = db.execute\n    saved(f"SELECT {user}")\n', ()),
    ("bound-parameter-shadow", 'def run(db):\n    submit = db.execute\n    def inner(submit, user):\n        return submit(f"SELECT {user}")\n    return inner\n', ()),
    ("bound-local-function-shadow", 'def run(db, user):\n    submit = db.execute\n    def inner():\n        def submit(query):\n            return len(query)\n        return submit(f"SELECT {user}")\n    return inner()\n', ()),
    ("bound-application-method", 'class Formatter:\n    def execute(self, query):\n        return len(query)\n    def run(self, user):\n        submit = self.execute\n        return submit(f"SELECT {user}")\n', ()),
    ("bound-application-raw-method", 'class Formatter:\n    def raw(self, text):\n        return len(text)\n    def run(self, user):\n        render = self.raw\n        return render(f"SELECT {user}")\n', ()),
    ("bound-application-extra-method", 'class Formatter:\n    def extra(self, text):\n        return len(text)\n    def run(self, user):\n        render = self.extra\n        return render(f"SELECT {user}")\n', ()),
    ("bound-application-receiver-rebound", 'class Formatter:\n    def execute(self, query):\n        return len(query)\n    def run(self, db, user):\n        submit = self.execute\n        self = db\n        return submit(f"SELECT {user}")\n', ()),
    ("bound-application-method-replaced-after-capture", 'class Formatter:\n    def raw(self, text):\n        return len(text)\n    def run(self, user):\n        render = self.raw\n        self.raw = len\n        return render(f"SELECT {user}")\n', ()),
    ("bound-application-function", 'def execute(query):\n    return len(query)\ndef run(user):\n    submit = execute\n    return submit(f"SELECT {user}")\n', ()),
    ("ordinary-raw-property", 'def render(record):\n    return record.raw\n', ()),
    ("ordinary-extra-property", 'def render(record):\n    return record.extra\n', ()),
    ("ordinary-raw-property-alias", 'def render(record, user):\n    raw = record.raw\n    return raw, f"SELECT {user}"\n', ()),
    ("ordinary-extra-property-container", 'def render(record):\n    return {"extra": record.extra}\n', ()),
    ("ordinary-raw-bound-parameter", 'def run(db, record):\n    db.execute("SELECT ?", (record.raw,))\n', ()),
    ("ordinary-extra-bound-parameter", 'def run(db, record):\n    submit = db.execute\n    submit("SELECT ?", (record.extra,))\n', ()),
    ("ordinary-raw-container-bound-data", 'def run(db, record):\n    values = [record.raw]\n    return db.execute("SELECT ?", (values[0],))\n', ()),
    ("ordinary-raw-property-and-sql-text", 'def render(record, user):\n    return {"raw": record.raw, "sql": f"SELECT {user}"}\n', ()),
    ("ordinary-extra-property-in-sql-text", 'def render(record, user):\n    extra = record.extra\n    return f"SELECT {user} {extra}"\n', ()),
    ("ordinary-raw-print-data", 'def render(record):\n    print("SELECT 1", record.raw)\n', ()),
    ("ordinary-extra-print-data", 'def render(record):\n    print("SELECT 1", record.extra)\n', ()),
    ("ordinary-raw-print-alias-data", 'def render(record):\n    output = print\n    output("SELECT 1", record.raw)\n', ()),
    ("ordinary-raw-str-data", 'def render(record):\n    return str(record.raw, "SELECT 1")\n', ()),
    ("ordinary-extra-format-data", 'def render(record):\n    return format(record.extra, "SELECT 1")\n', ()),
    ("ordinary-callback-storage", 'def run(user):\n    callbacks = [len]\n    return callbacks[0](f"SELECT {user}")\n', ()),
    ("ordinary-callback-parameter", 'def run(invoke, user):\n    return invoke(f"SELECT {user}")\n', ()),
    ("ordinary-getattr-lookalike", 'def getattr(obj, name):\n    return len\ndef run(user):\n    submit = getattr(None, "execute")\n    return submit(f"SELECT {user}")\n', ()),
    ("kwargs-direct-query", 'def run(db, user):\n    db.execute(**{"query": f"SELECT {user}"})\n', ((CRITICAL, 2),)),
    ("kwargs-saved-query", 'def run(db, user):\n    submit = db.execute\n    submit(**{"query": f"SELECT {user}"})\n', ((CRITICAL, 3),)),
    ("kwargs-direct-statement", 'def run(db, user):\n    db.exec_driver_sql(**{"statement": f"SELECT {user}"})\n', ((CRITICAL, 2),)),
    ("kwargs-fragment", 'def run(queryset, user):\n    queryset.extra(**{"where": [f"name = {user}"]})\n', ((CRITICAL, 2),)),
    ("kwargs-bound-data", 'def run(db, user):\n    db.execute(**{"query": "SELECT ?", "params": (f"SELECT {user}",)})\n', ()),
    ("kwargs-saved-bound-data", 'def run(db, user):\n    submit = db.execute\n    submit(**{"query": "SELECT ?", "params": (f"SELECT {user}",)})\n', ()),
    ("kwargs-fragment-bound-data", 'def run(queryset, user):\n    queryset.extra(**{"where": ["name = %s"], "params": (f"SELECT {user}",)})\n', ()),
)

# These programs pass a real SQL capability beyond the currently modeled
# call shapes. A partial result is honest; an empty complete scan is not.
# Stable call shapes above are required to finish with their exact labels.
BOUND_SQL_PARTIAL_CASES = (
    ("conditional-alias", 'def run(db, user, flag):\n    submit = db.execute\n    if flag:\n        submit = print\n    submit(f"SELECT {user}")\n', []),
    ("conditional-creation", 'def run(db, user, flag):\n    if flag:\n        submit = db.execute\n    else:\n        submit = print\n    submit(f"SELECT {user}")\n', []),
    ("eager-map-callback", 'def run(db, user):\n    return list(map(db.execute, [f"SELECT {user}"]))\n', []),
    ("unknown-callback-consumer", 'def run(db, user, invoke):\n    return invoke(db.execute, f"SELECT {user}")\n', []),
    ("returned-execution-callable", 'def callback(db):\n    return db.execute\ndef run(db, user):\n    submit = callback(db)\n    return submit(f"SELECT {user}")\n', []),
    ("container-callback", 'def run(db, user):\n    callbacks = [db.execute]\n    callbacks[0](f"SELECT {user}")\n', []),
    ("keyword-callback", 'def run(db, user, invoke):\n    return invoke(fn=db.execute, query=f"SELECT {user}")\n', []),
    ("callable-default", 'import sqlite3\ndb = sqlite3.connect(":memory:")\ndef run(user, submit=db.execute):\n    return submit(f"SELECT {user}")\n', []),
    ("walrus-target", 'def run(db, user):\n    return (submit := db.execute)(f"SELECT {user}")\n', []),
    ("conditional-expression", 'def run(db, user, flag):\n    submit = db.execute if flag else db.executescript\n    submit(f"SELECT {user}")\n', []),
    ("literal-getattr", 'def run(db, user):\n    submit = getattr(db, "execute")\n    submit(f"SELECT {user}")\n', []),
    ("local-getattr-alias", 'def run(db, user):\n    getter = getattr\n    submit = getter(db, "execute")\n    return submit(f"SELECT {user}")\n', []),
    ("imported-getattr-alias", 'from builtins import getattr as grab\ndef run(db, user):\n    submit = grab(db, "execute")\n    return submit(f"SELECT {user}")\n', []),
    ("imported-attrgetter-alias", 'from operator import attrgetter as grab\ndef run(db, user):\n    submit = grab("execute")(db)\n    return submit(f"SELECT {user}")\n', []),
    ("imported-methodcaller-alias", 'from operator import methodcaller as invoke\ndef run(db, user):\n    return invoke("execute", f"SELECT {user}")(db)\n', []),
    ("raw-container-callback", 'def run(qs, user):\n    callbacks = [qs.raw]\n    return callbacks[0](f"SELECT {user}")\n', []),
    ("extra-container-callback", 'def run(qs, user):\n    callbacks = [qs.extra]\n    return callbacks[0](where=[f"id = {user}"])\n', []),
    ("raw-keyword-callback", 'def run(qs, user, invoke):\n    return invoke(fn=qs.raw, query=f"SELECT {user}")\n', []),
    ("extra-keyword-callback", 'def run(qs, user, invoke):\n    return invoke(fn=qs.extra, where=[f"id = {user}"])\n', []),
    ("returned-raw-capability", 'def make(qs):\n    return qs.raw\ndef run(qs, user):\n    submit = make(qs)\n    return submit(f"SELECT {user}")\n', []),
    ("default-raw-capability", 'def run(qs, user):\n    def submit(value, raw=qs.raw):\n        return raw(value)\n    return submit(f"SELECT {user}")\n', []),
    ("raw-key-callback", 'def run(qs, user):\n    queries = [f"SELECT {user}"]\n    return min(queries, key=qs.raw)\n', []),
    ("extra-key-callback", 'def run(qs, user):\n    fragments = [{"flag": f"name = {user}"}]\n    return sorted(fragments, key=qs.extra)\n', []),
    ("shadowed-print-callback", 'def run(qs, user, print):\n    return print(qs.raw, f"SELECT {user}")\n', []),
    ("replaced-builtin-print-callback", 'import builtins\ndef run(qs, user):\n    def invoke(fn, query):\n        return fn(query)\n    builtins.print = invoke\n    return print(qs.raw, f"SELECT {user}")\n', []),
    ("metadata-replaces-saved-query-contract", 'class Wrapper:\n    def __init__(self, cursor):\n        self.cursor = cursor\n    def execute(self, query, params=()):\n        return len(query)\n    def replacement(self, query, params=()):\n        return self.cursor.execute(params[0])\ndef run(cursor, user):\n    wrapper = Wrapper(cursor)\n    submit = wrapper.execute\n    Wrapper.execute.__code__ = Wrapper.replacement.__code__\n    return submit("SELECT 1", (f"SELECT {user}",))\n', []),
    ("metadata-activates-captured-default", 'def run(cursor, user):\n    class Wrapper:\n        def __init__(self):\n            self.cursor = cursor\n        def execute(self, query, params=(f"SELECT {user}",)):\n            return len(query)\n        def replacement(self, query, params=()):\n            return self.cursor.execute(params[0])\n    wrapper = Wrapper()\n    submit = wrapper.execute\n    Wrapper.execute.__code__ = Wrapper.replacement.__code__\n    return submit("SELECT 1")\n', []),
    ("property-changes-query-family", 'class Wrapper:\n    @property\n    def execute(self):\n        return qs.extra\n    def run(self, user):\n        return self.execute(None, [f"name = {user}"])\n', []),
    ("reflected-local-method-replacement", 'class Formatter:\n    def execute(self, query):\n        return len(query)\n    def run(self, db, user):\n        setattr(self, "execute", db.execute)\n        submit = self.execute\n        return submit(f"SELECT {user}")\n', []),
    ("unknown-keyword-slot", 'def run(db, options):\n    db.execute(**options)\n', []),
    ("unknown-fragment-keywords", 'def run(queryset, options):\n    queryset.extra(**options)\n', []),
    ("retained-before-callback", 'def run(db, user, invoke):\n    db.execute(f"SELECT {user}")\n    invoke(db.execute, f"SELECT {user}")\n', [2]),
    ("retained-before-unknown-keywords", 'def run(db, user, options):\n    db.execute(f"SELECT {user}")\n    db.execute(**options)\n', [2]),
    ("known-keyword-overwritten-by-opaque-map", 'def run(db, options):\n    db.execute(**{"query": "SELECT 1", **options})\n', []),
)

# Literal dictionaries capture each value when that entry is evaluated.
# Repeated dictionary keys keep the last value; duplicate names across call
# expansions prevent invocation while preserving eager argument side effects.
KEYWORD_CAPTURE_CASES = (
    ("kwargs-earlier-value-taints-query", 'def run(db, user):\n    query = "SELECT 1"\n    db.execute(**{"params": ((query := f"SELECT {user}"),), "query": query})\n', ((CRITICAL, 3),)),
    ("kwargs-later-value-cannot-taint-query", 'def run(db, user):\n    query = "SELECT 1"\n    db.execute(**{"query": query, "params": ((query := f"SELECT {user}"),)})\n', ()),
    ("kwargs-earlier-value-cleans-query", 'def run(db, user):\n    query = f"SELECT {user}"\n    db.execute(**{"params": ((query := "SELECT 1"),), "query": query})\n', ()),
    ("kwargs-later-value-cannot-clean-query", 'def run(db, user):\n    query = f"SELECT {user}"\n    db.execute(**{"query": query, "params": ((query := "SELECT 1"),)})\n', ((CRITICAL, 3),)),
    ("kwargs-separate-expansion-capture", 'def run(db, user):\n    query = f"SELECT {user}"\n    db.execute(**{"query": query}, **{"params": ((query := "SELECT 1"),)})\n', ((CRITICAL, 3),)),
    ("kwargs-separate-expansion-earlier-write", 'def run(db, user):\n    query = "SELECT 1"\n    db.execute(**{"params": ((query := f"SELECT {user}"),)}, **{"query": query})\n', ((CRITICAL, 3),)),
    ("kwargs-duplicate-key-cleans", 'def run(db, user):\n    db.execute(**{"query": f"SELECT {user}", "query": "SELECT 1"})\n', ()),
    ("kwargs-duplicate-key-taints", 'def run(db, user):\n    db.execute(**{"query": "SELECT 1", "query": f"SELECT {user}"})\n', ((CRITICAL, 2),)),
    ("kwargs-nested-map-cleans", 'def run(db, user):\n    db.execute(**{"query": f"SELECT {user}", **{"query": "SELECT 1"}})\n', ()),
    ("kwargs-nested-map-taints", 'def run(db, user):\n    db.execute(**{"query": "SELECT 1", **{"query": f"SELECT {user}"}})\n', ((CRITICAL, 2),)),
    ("kwargs-opaque-map-then-fixed-query", 'def run(db, options):\n    db.execute(**{**options, "query": "SELECT 1"})\n', ()),
    ("kwargs-duplicate-expansions-prevent-call", 'def run(db, user):\n    db.execute(**{"query": f"SELECT {user}"}, **{"query": "SELECT 1"})\n', ()),
    ("kwargs-explicit-duplicate-prevents-call", 'def run(db, user):\n    db.execute(query=f"SELECT {user}", **{"query": "SELECT 1"})\n', ()),
    ("kwargs-nonstring-key-prevents-call", 'def run(db, user):\n    db.execute(**{"query": f"SELECT {user}", 0: None})\n', ()),
    ("kwargs-duplicate-keeps-eager-sink", 'def run(db, other, user):\n    db.execute(**{"query": "SELECT 1"}, **{"query": other.execute(f"SELECT {user}")})\n', ((CRITICAL, 2),)),
)

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
) + BOUND_SQL_CASES + KEYWORD_CAPTURE_CASES


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

    def test_saved_sql_capability_escape_is_explicitly_incomplete(self):
        for name, source, retained_lines in BOUND_SQL_PARTIAL_CASES:
            with self.subTest(case=name):
                path = self.artifacts / ('bound-incomplete-' + name + '.py')
                path.write_text(source, encoding='utf-8')
                findings = []
                previous = os.environ.pop(detector.SANITIZER_ENV, None)
                try:
                    with self.assertRaisesRegex(detector.SQLFlowLimit, 'incomplete'):
                        findings.extend(detector.find([path]))
                finally:
                    if previous is not None:
                        os.environ[detector.SANITIZER_ENV] = previous
                actual = sorted((rule, line) for rule, _, line, _, _ in findings)
                self.assertEqual(actual, [(CRITICAL, line) for line in retained_lines], source)

    def test_saved_sqlite_callable_keeps_receiver_and_parameter_binding(self):
        with sqlite3.connect(':memory:') as connection:
            connection.execute('CREATE TABLE accounts (name TEXT)')
            connection.executemany('INSERT INTO accounts VALUES (?)', [('alice',), ('bob',)])
            receiver = connection
            submit = receiver.execute
            saved = submit
            receiver = object()
            submit = len
            attacker = "alice' OR 1=1 --"
            unsafe = saved("SELECT name FROM accounts WHERE name = '" + attacker + "'").fetchall()
            bound = saved('SELECT name FROM accounts WHERE name = ?', (attacker,)).fetchall()
            self.assertEqual(unsafe, [('alice',), ('bob',)])
            self.assertEqual(bound, [])

    def test_literal_reducer_admission_includes_saved_sql_capabilities(self):
        namespace = ('import importlib\n'
                     'def load_plugin(name):\n    return importlib.import_module(name)\n'
                     'sum(item for item in (1, 2))\n')
        selected = {'bound-execute-alias', 'bound-saved-before-replacement',
                    'bound-nested-capture', 'bound-extra-predicate',
                    'conditional-alias', 'eager-map-callback', 'container-callback',
                    'keyword-callback', 'callable-default', 'walrus-target',
                    'conditional-expression', 'literal-getattr',
                    'local-getattr-alias', 'imported-getattr-alias',
                    'imported-attrgetter-alias', 'imported-methodcaller-alias',
                    'raw-container-callback', 'extra-container-callback',
                    'raw-keyword-callback', 'extra-keyword-callback',
                    'returned-raw-capability', 'default-raw-capability',
                    'raw-key-callback', 'extra-key-callback', 'shadowed-print-callback',
                    'replaced-builtin-print-callback',
                    'metadata-replaces-saved-query-contract', 'metadata-activates-captured-default',
                    'property-changes-query-family',
                    'reflected-local-method-replacement'}
        for name, body, _ in BOUND_SQL_CASES + BOUND_SQL_PARTIAL_CASES:
            if name not in selected:
                continue
            with self.subTest(capability=name):
                path = self.artifacts / ('literal-reducer-capability-' + name + '.py')
                # The final literal cannot certify an earlier hidden dynamic
                # sink or escaped callable as a file containing only fixed SQL.
                path.write_text(namespace + body + '\ncursor.execute("SELECT 1")\n', encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'incomplete'):
                    list(detector.find([path]))

    def test_literal_reducer_admission_keeps_non_sql_values_and_bound_parameters(self):
        namespace = ('import importlib\n'
                     'def load_plugin(name):\n    return importlib.import_module(name)\n'
                     'sum(item for item in (1, 2))\n')
        selected = {'bound-parameterized', 'bound-unused',
                    'ordinary-raw-property', 'ordinary-extra-property',
                    'ordinary-extra-property-container', 'ordinary-raw-bound-parameter',
                    'ordinary-extra-bound-parameter', 'ordinary-raw-container-bound-data',
                    'ordinary-raw-property-and-sql-text', 'ordinary-extra-property-in-sql-text'}
        for name, body, _ in BOUND_SQL_CASES:
            if name not in selected:
                continue
            with self.subTest(value=name):
                path = self.artifacts / ('literal-reducer-non-sql-' + name + '.py')
                path.write_text(namespace + body + '\ncursor.execute("SELECT 1")\n', encoding='utf-8')
                self.assertEqual(list(detector.find([path])), [])

    def test_literal_reducer_data_consumers_require_closed_builtin_identity(self):
        namespace = ('import importlib\n'
                     'def load_plugin(name):\n    return importlib.import_module(name)\n'
                     'sum(item for item in (1, 2))\n')
        selected = {'ordinary-raw-print-data', 'ordinary-extra-print-data',
                    'ordinary-raw-print-alias-data', 'ordinary-raw-str-data',
                    'ordinary-extra-format-data'}
        for name, body, _ in BOUND_SQL_CASES:
            if name not in selected:
                continue
            with self.subTest(consumer=name):
                path = self.artifacts / ('literal-reducer-open-builtin-' + name + '.py')
                # These same field values are clean with closed builtins.
                # Namespace exposure removes that identity proof: a replaced
                # print/str/format may invoke the supplied SQL capability.
                path.write_text(namespace + body + '\ncursor.execute("SELECT 1")\n', encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'incomplete'):
                    list(detector.find([path]))

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

    def test_large_binding_index_omits_only_operator_and_context_tags(self):
        # A non-SQL use of the admitted name still needs the full lexical
        # index. Its marker leaves do not describe additional program state.
        source = 'value = extra + right * (extra - right)\n' * 7000
        tree = ast.parse(source)
        self.assertGreater(sum(1 for _ in ast.walk(tree)), 100_000)
        path = self.artifacts / 'large-ordinary-extra.py'
        path.write_text(source, encoding='utf-8')
        self.assertEqual(list(detector.find([path])), [])
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'binding budget.*incomplete'):
            list(detector.find([path], max_steps=1))

    def test_large_source_default_does_not_override_explicit_budget(self):
        path = self.artifacts / 'large-index-budget.py'
        path.write_text('value = extra + right * (extra - right)\n' * 12000, encoding='utf-8')
        self.assertEqual(list(detector.find([path])), [])
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'binding budget.*incomplete'):
            list(detector.find([path], max_steps=100_000))

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
        ) + tuple((name, source, retained_lines, 'incomplete')
                  for name, source, retained_lines in BOUND_SQL_PARTIAL_CASES
                  if name in {'keyword-callback', 'unknown-keyword-slot',
                              'retained-before-callback', 'retained-before-unknown-keywords'})
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
                    'imported-sql-alias-local-copy', 'imported-sql-alias-parameter-shadow',
                    'bound-execute-alias', 'bound-extra-predicate',
                    'bound-saved-before-replacement', 'bound-sql-looking-data',
                    'bound-alias-sql-looking-data',
                    'bound-application-raw-method', 'ordinary-raw-bound-parameter',
                    'kwargs-direct-query', 'kwargs-saved-bound-data'}
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
