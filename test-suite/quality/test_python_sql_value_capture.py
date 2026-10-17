#!/usr/bin/env python3
"""SQL value capture regressions with independent SQLite execution witnesses.

Complements the incumbent sink-argument/control-flow corpus. Expected findings
come from the value reaching the SQL argument, never the final variable store.
Only test-authored code is executed, against an in-memory database.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'modules/helpers'))
from ubs_core.py_detectors import sql_injection as detector

CRITICAL = 'py.security.sql-injection'
WARNING = 'py.security.sql-injection-unproven'

# The wrapper contributes exactly one line; locations below are explicit.
CASES = (
    ('predicate-alias', '    clause = f"name = {user}"\n    saved = clause\n    clause = "id = 1"\n    qs.extra(where=[saved])\n', ((CRITICAL, 5),)),
    ('predicate-kill', '    clause = f"name = {user}"\n    clause = "id = 1"\n    qs.extra(where=[clause])\n', ()),
    ('predicate-bound-data', '    clause = f"name = {user}"\n    qs.extra(where=["name = %s"], params=[clause])\n', ()),
    ('select-values', '    columns = {"flag": f"name = {user}"}\n    saved = columns\n    columns = {"flag": "1"}\n    qs.extra(select=saved)\n', ((CRITICAL, 5),)),
    ('select-keys', '    columns = {f"SELECT {user}": "1"}\n    qs.extra(select=columns)\n', ()),
    ('template-format', '    template = "SELECT {}"\n    cursor.execute(template.format(user))\n', ((CRITICAL, 3),)),
    ('template-percent', '    template = "SELECT %s"\n    cursor.execute(template % user)\n', ((CRITICAL, 3),)),
    ('template-format-map', '    template = "SELECT {value}"\n    cursor.execute(template.format_map({"value": user}))\n', ((CRITICAL, 3),)),
    ('template-static', '    template = "SELECT {}"\n    cursor.execute(template.format(1))\n', ()),
    ('template-kill', '    template = "SELECT {}"\n    template = "hello {}"\n    cursor.execute(template.format(user))\n', ()),
    ('augmented-sql', '    query = "SELECT "\n    query += user\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('augmented-static', '    query = "SELECT "\n    query += "1"\n    cursor.execute(query)\n', ()),
    ('swap', '    safe = "SELECT 1"\n    unsafe = f"SELECT {user}"\n    safe, unsafe = unsafe, safe\n    cursor.execute(safe)\n    cursor.execute(unsafe)\n', ((CRITICAL, 5),)),
    ('early-keyword-taints', '    query = "SELECT 1"\n    cursor.execute(params=((query := f"SELECT {user}"),)[:0], query=query)\n', ((CRITICAL, 3),)),
    ('early-keyword-cleans', '    query = f"SELECT {user}"\n    cursor.execute(params=((query := "SELECT 1"),)[:0], query=query)\n', ()),
    ('late-keyword-cannot-clean', '    query = f"SELECT {user}"\n    cursor.execute(query=query, params=((query := "SELECT 1"),)[:0])\n', ((CRITICAL, 3),)),
    ('late-keyword-cannot-taint', '    query = "SELECT 1"\n    cursor.execute(query=query, params=((query := f"SELECT {user}"),)[:0])\n', ()),
    ('sql-walrus-clean', '    query = f"SELECT {user}"\n    cursor.execute((query := "SELECT 1"))\n', ()),
    ('tuple-capture', '    query = f"SELECT {user}"\n    saved, other = query, (query := "SELECT 1")\n    cursor.execute(saved)\n', ((CRITICAL, 4),)),
    ('tuple-clean-capture', '    query = "SELECT 1"\n    saved, other = query, (query := f"SELECT {user}")\n    cursor.execute(saved)\n', ()),
    ('dictionary-order', '    clause = f"name = {user}"\n    columns = {"first": clause, str((clause := "id = 1")): "1"}\n    qs.extra(select=columns)\n', ((CRITICAL, 4),)),
    ('dictionary-key-first', '    clause = f"name = {user}"\n    columns = {str((clause := "id = 1")): clause}\n    qs.extra(select=columns)\n', ()),
    ('format-receiver-capture', '    template = "SELECT {}"\n    query = template.format((template := "hello {}") and user)\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('untaken-conditional', '    cursor.execute(f"SELECT {user}" if False else "SELECT 1")\n', ()),
    ('short-circuit-clean', '    query = "SELECT 1" or f"SELECT {user}"\n    cursor.execute(query)\n', ()),
    ('short-circuit-unsafe', '    query = False or f"SELECT {user}"\n    cursor.execute(query)\n', ((CRITICAL, 3),)),
    ('augmented-left-capture', '    query = f"SELECT {user}"\n    query += (query := " ")\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('backedge-refresh', '    query = "SELECT 1"\n    for row in rows:\n        cursor.execute(query=query)\n        query = f"SELECT {user}"\n', ((CRITICAL, 4),)),
    ('unknown-fragment', '    clause = f"name = {UNKNOWN}"\n    qs.extra(where=[clause])\n', ((WARNING, 3),)),
    ('overwritten-parameter', '    user = 1\n    cursor.execute(f"SELECT {user}")\n', ()),
    ('bound-after-write', '    cursor.execute(params=((query := f"SELECT {user}"),), query="SELECT %s")\n', ()),
    ('same-line-sinks', '    query = f"SELECT {user}"\n    for row in rows:\n        cursor.execute(query); cursor.execute(query)\n', ((CRITICAL, 4), (CRITICAL, 4))),
)


CASES += (
    ('comp-tainted-item', '    queries = [f"SELECT {item}" for item in [user]]\n    for query in queries:\n        cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('comp-static-shadow', '    queries = [f"SELECT {user}" for user in [1]]\n    for query in queries:\n        cursor.execute(query)\n', ()),
    ('comp-static-projection', '    queries = ["SELECT 1" for item in [f"SELECT {user}"]]\n    for query in queries:\n        cursor.execute(query)\n', ()),
    ('comp-empty-keeps-outer', '    query = f"SELECT {user}"\n    unused = [(query := "SELECT 1") for item in []]\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('comp-nonempty-cleans-outer', '    query = f"SELECT {user}"\n    unused = [(query := "SELECT 1") for item in [1]]\n    cursor.execute(query)\n', ()),
    ('comp-false-filter-keeps-outer', '    query = f"SELECT {user}"\n    unused = [(query := "SELECT 1") for item in [1] if False]\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('comp-false-filter-does-not-taint', '    query = "SELECT 1"\n    unused = [(query := f"SELECT {user}") for item in [1] if False]\n    cursor.execute(query)\n', ()),
    ('comp-empty-skips-sink', '    unused = [cursor.execute(f"SELECT {user}") for item in []]\n', ()),
    ('comp-false-filter-skips-sink', '    unused = [cursor.execute(f"SELECT {user}") for item in [1] if False]\n', ()),
    ('comp-one-trip-no-backedge', '    query = "SELECT 1"\n    unused = [(cursor.execute(query), (query := f"SELECT {user}")) for item in [1]]\n', ()),
    ('comp-two-trips-real-backedge', '    query = "SELECT 1"\n    unused = [(cursor.execute(query), (query := f"SELECT {user}")) for item in [1, 2]]\n', ((CRITICAL, 3),)),
    ('comp-unknown-iteration-keeps-outer', '    query = f"SELECT {user}"\n    unused = [(query := "SELECT 1") for item in rows]\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('comp-unknown-iteration-backedge', '    query = "SELECT 1"\n    unused = [(cursor.execute(query), (query := f"SELECT {user}")) for item in rows]\n', ((CRITICAL, 3),)),
    ('comp-target-does-not-leak', '    query = f"SELECT {user}"\n    unused = [query for query in ["SELECT 1"]]\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('comp-target-does-not-taint-outer', '    query = "SELECT 1"\n    unused = [query for query in [f"SELECT {user}"]]\n    cursor.execute(query)\n', ()),
    ('comp-filter-write-retained', '    query = "SELECT 1"\n    unused = [None for item in [1] if (query := f"SELECT {user}") if False]\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('comp-filter-write-before-body', '    query = "SELECT 1"\n    unused = [cursor.execute(query) for item in [1] if (query := f"SELECT {user}")]\n', ((CRITICAL, 3),)),
    ('comp-filter-clean-before-body', '    query = f"SELECT {user}"\n    unused = [cursor.execute(query) for item in [1] if (query := "SELECT 1")]\n', ()),
    ('comp-dict-tainted-values', '    columns = {"flag": f"name = {item}" for item in [user]}\n    qs.extra(select=columns)\n', ((CRITICAL, 3),)),
    ('comp-dict-keys-not-sql', '    columns = {f"SELECT {item}": "1" for item in [user]}\n    qs.extra(select=columns)\n', ()),
    ('comp-set-tainted-values', '    clauses = {f"name = {item}" for item in [user]}\n    qs.extra(where=clauses)\n', ((CRITICAL, 3),)),
    ('comp-set-empty-keeps-outer', '    query = f"SELECT {user}"\n    unused = {(query := "SELECT 1") for item in []}\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('comp-nested-generators', '    queries = [f"SELECT {item}" for group in [[user]] for item in group]\n    for query in queries:\n        cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('comp-nested-static', '    queries = [f"SELECT {item}" for group in [[1]] for item in group]\n    for query in queries:\n        cursor.execute(query)\n', ()),
    ('comp-nested-empty', '    unused = [cursor.execute(f"SELECT {user}") for group in [1] for item in []]\n', ()),
    ('comp-empty-outer-skips-inner', '    unused = [cursor.execute(f"SELECT {user}") for group in [] for item in [1]]\n', ()),
    ('comp-first-iterable-in-outer-scope', '    query = f"SELECT {user}"\n    unused = [cursor.execute(query) for query in [query]]\n', ((CRITICAL, 3),)),
    ('comp-dict-key-before-value', '    query = f"SELECT {user}"\n    columns = {str((query := "SELECT 1")): query for item in [1]}\n    qs.extra(select=columns)\n', ()),
    ('comp-exception-restores-local', '    query = f"SELECT {user}"\n    try:\n        unused = [work() for query in ["SELECT 1"]]\n    except Exception:\n        cursor.execute(query)\n', ((CRITICAL, 6),)),
    ('comp-bound-values-remain-data', '    values = [f"SELECT {item}" for item in [user]]\n    cursor.execute("SELECT %s", values)\n', ()),
)


GENERATOR_CASES = (
    ('gen-unused-keeps-outer', '    query = f"SELECT {user}"\n    pending = ((query := "SELECT 1") for item in [1])\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('gen-unused-does-not-taint', '    query = "SELECT 1"\n    pending = ((query := f"SELECT {user}") for item in [1])\n    cursor.execute(query)\n', ()),
    ('gen-unused-sink-does-not-execute', '    pending = (cursor.execute(f"SELECT {user}") for item in [1])\n', ()),
    ('gen-first-iterable-is-eager', '    query = f"SELECT {user}"\n    pending = (None for item in [(query := "SELECT 1")])\n    cursor.execute(query)\n', ()),
    ('gen-first-iterable-sink-is-eager', '    pending = (None for item in [cursor.execute(f"SELECT {user}")])\n', ((CRITICAL, 2),)),
    ('gen-empty-never-runs-body', '    query = f"SELECT {user}"\n    pending = ((query := "SELECT 1") for item in [])\n    list(pending)\n    cursor.execute(query)\n', ((CRITICAL, 5),)),
    ('gen-drain-cleans-outer', '    query = f"SELECT {user}"\n    pending = ((query := "SELECT 1") for item in [1])\n    list(pending)\n    cursor.execute(query)\n', ()),
    ('gen-drain-taints-outer', '    query = "SELECT 1"\n    pending = ((query := f"SELECT {user}") for item in [1])\n    list(pending)\n    cursor.execute(query)\n', ((CRITICAL, 5),)),
    ('gen-yield-sees-later-write', '    query = "SELECT 1"\n    pending = (query for item in [1])\n    query = f"SELECT {user}"\n    qs.extra(where=list(pending))\n', ((CRITICAL, 5),)),
    ('gen-yield-sees-later-clean', '    query = f"SELECT {user}"\n    pending = (query for item in [1])\n    query = "SELECT 1"\n    qs.extra(where=list(pending))\n', ()),
    ('gen-iterable-captures-earlier-value', '    query = f"SELECT {user}"\n    pending = (item for item in [query])\n    query = "SELECT 1"\n    qs.extra(where=list(pending))\n', ((CRITICAL, 5),)),
    ('gen-iterable-captures-clean-value', '    query = "SELECT 1"\n    pending = (item for item in [query])\n    query = f"SELECT {user}"\n    qs.extra(where=list(pending))\n', ()),
    ('gen-alias-shares-exhaustion', '    pending = (f"name = {item}" for item in [user])\n    alias = pending\n    first = list(alias)\n    qs.extra(where=list(pending))\n    qs.extra(where=first)\n', ((CRITICAL, 6),)),
    ('gen-conditional-consumption', '    pending = (f"name = {item}" for item in [user])\n    if rows:\n        list(pending)\n    qs.extra(where=list(pending))\n', ((CRITICAL, 5),)),
    ('gen-both-branches-exhaust', '    pending = (f"name = {item}" for item in [user])\n    if rows:\n        list(pending)\n    else:\n        tuple(pending)\n    qs.extra(where=list(pending))\n', ()),
    ('gen-false-filter', '    query = f"SELECT {user}"\n    pending = ((query := "SELECT 1") for item in [1] if False)\n    tuple(pending)\n    cursor.execute(query)\n', ((CRITICAL, 5),)),
    ('gen-filter-write-at-consumption', '    query = f"SELECT {user}"\n    pending = (None for item in [1] if (query := "SELECT 1"))\n    cursor.execute(query)\n    tuple(pending)\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('gen-nested-iterable-is-lazy', '    query = f"SELECT {user}"\n    pending = (None for item in [1] for other in [(query := "SELECT 1")])\n    cursor.execute(query)\n    list(pending)\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
    ('gen-sink-at-consumption', '    query = "SELECT 1"\n    pending = (cursor.execute(query) for item in [1])\n    query = f"SELECT {user}"\n    list(pending)\n', ((CRITICAL, 3),)),
    ('gen-static-shadowing', '    qs.extra(where=list(f"id = {user}" for user in [1]))\n', ()),
    ('gen-safe-projection', '    qs.extra(where=list("id = 1" for item in [f"SELECT {user}"]))\n', ()),
    ('gen-direct-extra-consumes', '    qs.extra(where=(f"name = {item}" for item in [user]))\n', ((CRITICAL, 2),)),
    ('gen-iter-is-not-consumption', '    query = f"SELECT {user}"\n    pending = ((query := "SELECT 1") for item in [1])\n    alias = iter(pending)\n    cursor.execute(query)\n    list(alias)\n    cursor.execute(query)\n', ((CRITICAL, 5),)),
    ('gen-close-does-not-run-body', '    query = f"SELECT {user}"\n    pending = ((query := "SELECT 1") for item in [1])\n    pending.close()\n    list(pending)\n    cursor.execute(query)\n', ((CRITICAL, 6),)),
    ('gen-captured-argument-before-rebind', '    pending = (f"name = {item}" for item in [user])\n    alias = pending\n    qs.extra(where=alias, params=((pending := None),)[:0])\n', ((CRITICAL, 4),)),
    ('gen-raise-during-drain-closes-it', '    query = f"SELECT {user}"\n    pending = (work() for item in [1])\n    try:\n        list(pending)\n    except Exception:\n        qs.extra(where=list(pending))\n    cursor.execute(query)\n', ((CRITICAL, 8),)),
)


def program(body):
    return 'def run(cursor, qs, user, rows):\n' + body


class SQLValueCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        artifacts = ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        cls.artifacts = Path(tempfile.mkdtemp(prefix='sql-value-capture-', dir=artifacts))
        cls.identity = hashlib.sha256(Path(detector.__file__).read_bytes()).hexdigest()

    def inspect(self, name, source, expected):
        path = self.artifacts / (name + '.py')
        path.write_text(source, encoding='utf-8')
        started = time.perf_counter()
        with patch.dict(os.environ, {detector.SANITIZER_ENV: ''}):
            hits = list(detector.find([path]))
        actual = sorted((rule, line) for rule, _, line, _, _ in hits)
        (self.artifacts / (name + '.json')).write_text(json.dumps({
            'case': name, 'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'detector_sha256': self.identity, 'python': sys.version,
            'elapsed_seconds': time.perf_counter() - started,
            'expected': expected, 'actual': actual,
        }, indent=2) + '\n', encoding='utf-8')
        self.assertEqual(actual, sorted(expected), source)
        self.assertTrue(all(found == path and col == 1 for _, found, _, col, _ in hits))
        return path

    def test_value_capture_programs(self):
        for name, body, expected in CASES:
            with self.subTest(case=name):
                self.inspect(name, program(body), expected)

    def test_lazy_generator_programs(self):
        for name, body, expected in GENERATOR_CASES:
            with self.subTest(case=name):
                self.inspect(name, program(body), expected)

    def test_deferred_validator_is_not_an_executed_guard(self):
        sources = (
            'def run(cursor, user):\n    pending = (validate_sql_identifier(user) for item in [1])\n    cursor.execute(f"SELECT {user}")\n',
            'def check(user):\n    return (validate_sql_identifier(user) for item in [1])\ndef run(cursor, user):\n    check(user)\n    cursor.execute(f"SELECT {user}")\n',
        )
        for index, source in enumerate(sources):
            with self.subTest(case=index):
                path = self.artifacts / f'generator-validator-{index}.py'
                path.write_text(source, encoding='utf-8')
                with patch.dict(os.environ, {detector.SANITIZER_ENV: 'validate_sql_identifier'}):
                    hits = list(detector.find([path]))
                self.assertEqual([(rule, line) for rule, _, line, _, _ in hits],
                                 [(CRITICAL, len(source.splitlines()))])

    def test_generator_consumer_boundaries_are_explicit(self):
        bodies = (
            '    pending = (f"SELECT {item}" for item in [user])\n    consume(pending)\n',
            '    pending = (f"SELECT {item}" for item in [user])\n    next(pending)\n',
            '    pending = (f"SELECT {item}" for item in [user])\n    list = unknown\n    list(pending)\n',
            '    pending = (f"SELECT {item}" for item in [user])\n    if rows:\n        pending = None\n    list(pending)\n',
            '    pending = (f"SELECT {item}" for item in [user])\n    def nested():\n        list(pending)\n',
        )
        for index, body in enumerate(bodies):
            with self.subTest(case=index):
                path = self.artifacts / f'generator-boundary-{index}.py'
                path.write_text(program(body), encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator.*incomplete'):
                    list(detector.find([path]))

    def test_real_sqlite_lazy_generators(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        fixed = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        witnesses = (
            ('unused', f'    query = {unsafe}\n    pending = ((query := {fixed}) for item in [1])\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('drained', f'    query = {unsafe}\n    pending = ((query := {fixed}) for item in [1])\n    list(pending)\n    return cursor.execute(query).fetchone()[0]\n', 1, ()),
            ('late-taint', f'    query = {fixed}\n    pending = (query for item in [1])\n    query = {unsafe}\n    return cursor.execute(list(pending)[0]).fetchone()[0]\n', 2, ((CRITICAL, 5),)),
            ('late-clean', f'    query = {unsafe}\n    pending = (query for item in [1])\n    query = {fixed}\n    return cursor.execute(list(pending)[0]).fetchone()[0]\n', 1, ()),
            ('iterable-capture', f'    query = {unsafe}\n    pending = (item for item in [query])\n    query = {fixed}\n    return cursor.execute(list(pending)[0]).fetchone()[0]\n', 2, ((CRITICAL, 5),)),
            ('alias-exhaustion', f'    query = {unsafe}\n    pending = ((query := {fixed}) for item in [1])\n    alias = pending\n    list(pending)\n    query = {unsafe}\n    tuple(alias)\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 8),)),
            ('filtered', f'    query = {unsafe}\n    pending = ((query := {fixed}) for item in [1] if False)\n    list(pending)\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 5),)),
            ('closed', f'    query = {unsafe}\n    pending = ((query := {fixed}) for item in [1])\n    pending.close()\n    list(pending)\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 6),)),
        )
        for name, body, rows, expected in witnesses:
            with self.subTest(case=name):
                source = program(body)
                namespace = {}
                exec(compile(source, '<test-authored-generator>', 'exec'), namespace)
                connection = sqlite3.connect(':memory:')
                try:
                    connection.execute('CREATE TABLE users(name TEXT)')
                    connection.executemany('INSERT INTO users VALUES (?)', [('alice',), ('bob',)])
                    actual = namespace['run'](connection.cursor(), None, "' OR 1=1 --", [])
                finally:
                    connection.close()
                (self.artifacts / f'sqlite-generator-{name}-execution.json').write_text(json.dumps({
                    'case': name, 'expected_rows': rows, 'actual_rows': actual,
                    'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
                    'python': sys.version, 'sqlite_version': sqlite3.sqlite_version,
                }, indent=2) + '\n', encoding='utf-8')
                self.assertEqual(actual, rows)
                self.inspect('sqlite-generator-' + name, source, expected)

    def test_real_sqlite_values(self):
        class KeywordCursor:
            def __init__(self, cursor):
                self.cursor = cursor

            def execute(self, query, params=()):
                return self.cursor.execute(query, params)

        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        fixed = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        witnesses = (
            ('early-taint', f'    query = {fixed}\n    return cursor.execute(params=((query := {unsafe}),)[:0], query=query).fetchone()[0]\n', 2, ((CRITICAL, 3),)),
            ('early-clean', f'    query = {unsafe}\n    return cursor.execute(params=((query := {fixed}),)[:0], query=query).fetchone()[0]\n', 1, ()),
            ('late-taint', f'    query = {fixed}\n    return cursor.execute(query=query, params=((query := {unsafe}),)[:0]).fetchone()[0]\n', 1, ()),
            ('late-clean', f'    query = {unsafe}\n    return cursor.execute(query=query, params=((query := {fixed}),)[:0]).fetchone()[0]\n', 2, ((CRITICAL, 3),)),
            ('saved-unsafe', f'    query = {unsafe}\n    saved, other = query, (query := {fixed})\n    return cursor.execute(saved).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('saved-clean', f'    query = {fixed}\n    saved, other = query, (query := {unsafe})\n    return cursor.execute(saved).fetchone()[0]\n', 1, ()),
            ('bound-data', '    return cursor.execute("SELECT count(*) FROM users WHERE name = ?", (user,)).fetchone()[0]\n', 0, ()),
            ('left-capture', f'    query = {unsafe}\n    query += (query := " ")\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
        )
        for name, body, rows, expected in witnesses:
            with self.subTest(case=name):
                source = program(body)
                namespace = {'__builtins__': {}}
                exec(compile(source, name, 'exec'), namespace)
                connection = sqlite3.connect(':memory:')
                try:
                    cursor = connection.cursor()
                    cursor.execute('CREATE TABLE users (name TEXT)')
                    cursor.executemany('INSERT INTO users VALUES (?)', [('alice',), ('bob',)])
                    actual = namespace['run'](KeywordCursor(cursor), None, "' OR 1=1 --", [])
                finally:
                    connection.close()
                (self.artifacts / ('sqlite-' + name + '-execution.json')).write_text(json.dumps({
                    'sqlite_version': sqlite3.sqlite_version, 'expected_rows': rows,
                    'actual_rows': actual, 'python': sys.version,
                }, indent=2) + '\n', encoding='utf-8')
                self.assertEqual(actual, rows)
                self.inspect('sqlite-' + name, source, expected)

    def test_real_sqlite_comprehensions(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        fixed = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        witnesses = (
            ('empty-list', f'    query = {unsafe}\n    [(query := {fixed}) for item in []]\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('nonempty-list', f'    query = {unsafe}\n    [(query := {fixed}) for item in [1]]\n    return cursor.execute(query).fetchone()[0]\n', 1, ()),
            ('false-filter', f'    query = {unsafe}\n    [(query := {fixed}) for item in [1] if False]\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('filter-write', f'    query = {unsafe}\n    [1 for item in [1] if (query := {fixed}) and False]\n    return cursor.execute(query).fetchone()[0]\n', 1, ()),
            ('local-target', f'    query = {unsafe}\n    [query for query in [{fixed}]]\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('safe-projection', f'    queries = [{fixed} for item in [user]]\n    for query in queries:\n        return cursor.execute(query).fetchone()[0]\n', 1, ()),
            ('tainted-projection', f'    queries = [{unsafe} for user in [user]]\n    for query in queries:\n        return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('one-trip', f'    query = {fixed}\n    values = [(cursor.execute(query).fetchone()[0], (query := {unsafe}))[0] for item in [1]]\n    return values[-1]\n', 1, ()),
            ('two-trips', f'    query = {fixed}\n    values = [(cursor.execute(query).fetchone()[0], (query := {unsafe}))[0] for item in [1, 2]]\n    return values[-1]\n', 2, ((CRITICAL, 3),)),
            ('empty-set', f'    query = {unsafe}\n    {{(query := {fixed}) for item in []}}\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('dictionary-order', f'    query = {unsafe}\n    {{(query := {fixed}): query for item in [1]}}\n    return cursor.execute(query).fetchone()[0]\n', 1, ()),
            ('nested-empty', f'    query = {unsafe}\n    [(query := {fixed}) for group in [1] for item in []]\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
        )
        for name, body, rows, expected in witnesses:
            with self.subTest(case=name):
                source = program(body)
                namespace = {'__builtins__': {}}
                exec(compile(source, name, 'exec'), namespace)
                connection = sqlite3.connect(':memory:')
                try:
                    cursor = connection.cursor()
                    cursor.execute('CREATE TABLE users (name TEXT)')
                    cursor.executemany('INSERT INTO users VALUES (?)', [('alice',), ('bob',)])
                    actual = namespace['run'](cursor, None, "' OR 1=1 --", [])
                finally:
                    connection.close()
                (self.artifacts / ('sqlite-comp-' + name + '-execution.json')).write_text(json.dumps({
                    'sqlite_version': sqlite3.sqlite_version, 'expected_rows': rows,
                    'actual_rows': actual, 'python': sys.version,
                }, indent=2) + '\n', encoding='utf-8')
                self.assertEqual(actual, rows)
                self.inspect('sqlite-comp-' + name, source, expected)

    def test_async_comprehension_flow(self):
        cases = (
            ('async-projection', '    queries = [f"SELECT {user}" async for item in rows]\n    for query in queries:\n        cursor.execute(query)\n', ((CRITICAL, 4),)),
            ('async-static-projection', '    queries = ["SELECT 1" async for item in rows]\n    for query in queries:\n        cursor.execute(query)\n', ()),
            ('async-zero-trip', '    query = f"SELECT {user}"\n    [(query := "SELECT 1") async for item in rows]\n    cursor.execute(query)\n', ((CRITICAL, 4),)),
        )
        for name, body, expected in cases:
            with self.subTest(case=name):
                self.inspect(name, 'async ' + program(body), expected)

    def test_comprehension_budget_is_not_clean(self):
        source = program('    queries = [f"SELECT {user}" for item in rows]\n    cursor.execute(queries[0])\n')
        path = self.artifacts / 'comp-budget.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'budget.*incomplete'):
            list(detector.find([path], max_steps=2))

    @unittest.skipUnless((ROOT / 'ubs').is_file(), 'real CLI requires full checkout')
    def test_real_cli_capture(self):
        selected = {'predicate-alias', 'predicate-kill', 'early-keyword-taints',
                    'early-keyword-cleans', 'tuple-capture', 'tuple-clean-capture',
                    'comp-tainted-item', 'comp-static-projection',
                    'comp-empty-keeps-outer', 'comp-nonempty-cleans-outer',
                    'gen-unused-keeps-outer', 'gen-drain-cleans-outer',
                    'gen-yield-sees-later-write', 'gen-yield-sees-later-clean',
                    'gen-alias-shares-exhaustion'}
        for name, body, expected in CASES + GENERATOR_CASES:
            if name not in selected:
                continue
            for entry in ('ubs', 'modules/ubs-python.sh'):
                for fmt in ('json', 'sarif'):
                    with self.subTest(case=name, entry=entry, format=fmt):
                        folder = self.artifacts / (name + '-' + entry.replace('/', '-') + '-' + fmt)
                        folder.mkdir()
                        source = folder / 'case.py'
                        source.write_text(program(body), encoding='utf-8')
                        for child in ('home', 'cache', 'tmp'):
                            (folder / child).mkdir()
                        skip = ','.join(str(n) for n in range(1, 24) if n != 7)
                        env = {key: value for key, value in os.environ.items() if not key.startswith('UBS_')}
                        env.update(HOME=str(folder / 'home'), XDG_CACHE_HOME=str(folder / 'cache'),
                                   TMPDIR=str(folder / 'tmp'), UBS_KEEP_TEMP='1', UBS_NO_CACHE='1',
                                   UBS_NO_AUTO_UPDATE='1', UBS_SKIP_CATEGORIES=skip, ENABLE_UV_TOOLS='0',
                                   PYTHONDONTWRITEBYTECODE='1', NO_COLOR='1')
                        command = ['bash', str(ROOT / entry), '--ci', '--no-color', '--format=' + fmt,
                                   '--skip=' + skip, '--only=python' if entry == 'ubs' else '--no-uv', str(source)]
                        started = time.perf_counter()
                        try:
                            result = subprocess.run(command, cwd=folder, env=env, capture_output=True,
                                                    text=True, timeout=120, check=False)
                        except subprocess.TimeoutExpired as exc:
                            (folder / 'stdout.log').write_bytes(exc.stdout or b'')
                            (folder / 'stderr.log').write_bytes(exc.stderr or b'')
                            self.fail(f'CLI timeout: {command}; evidence: {folder}')
                        (folder / 'stdout.log').write_text(result.stdout, encoding='utf-8')
                        (folder / 'stderr.log').write_text(result.stderr, encoding='utf-8')
                        (folder / 'run.json').write_text(json.dumps({
                            'command': command, 'status': result.returncode, 'detector_sha256': self.identity,
                            'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                            'entry_sha256': hashlib.sha256((ROOT / entry).read_bytes()).hexdigest(),
                            'elapsed_seconds': time.perf_counter() - started,
                        }, indent=2) + '\n', encoding='utf-8')
                        self.assertEqual(result.returncode, 1 if expected else 0, result.stderr)
                        document = json.loads(result.stdout)
                        actual = []
                        if fmt == 'json':
                            scans = document['scanners'] if entry == 'ubs' else [document]
                            self.assertEqual(len(scans), 1)
                            scan = scans[0]
                            self.assertEqual((scan['status'], scan['files']), ('ok', 1))
                            for severity in ('critical', 'warning', 'info'):
                                self.assertEqual(scan[severity], sum(f['count'] for f in scan['findings'] if f['severity'] == severity))
                            for finding in scan['findings']:
                                rule = finding.get('rule_id', finding.get('rule'))
                                if rule in {CRITICAL, WARNING}:
                                    self.assertEqual(finding['count'], len(finding['samples']))
                                    for sample in finding['samples']:
                                        self.assertEqual(Path(sample['file']).name, source.name)
                                        actual.append((rule, sample['line']))
                        else:
                            for run in document['runs']:
                                for finding in run.get('results', []):
                                    if finding['ruleId'] in {CRITICAL, WARNING}:
                                        location = finding['locations'][0]['physicalLocation']
                                        self.assertEqual(Path(unquote(location['artifactLocation']['uri'])).name, source.name)
                                        self.assertEqual(location['region']['startColumn'], 1)
                                        actual.append((finding['ruleId'], location['region']['startLine']))
                        self.assertEqual(sorted(actual), sorted(expected), folder)


if __name__ == '__main__':
    unittest.main(verbosity=2)
