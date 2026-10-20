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
            '    pending = ((query := f"SELECT {item}") for item in [user])\n    next(pending)\n',
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

    def test_next_projection_preserves_sql_risk(self):
        cases = (
            ('unused-next', '    pending = (f"SELECT {item}" for item in [user])\n    next(pending)\n', ()),
            ('unsafe-next', '    pending = (f"SELECT {item}" for item in [user])\n    cursor.execute(next(pending))\n', ((CRITICAL, 3),)),
            ('safe-next', '    pending = ("SELECT 1" for item in rows)\n    cursor.execute(next(pending))\n', ()),
            ('unsafe-default', '    pending = ("SELECT 1" for item in [])\n    cursor.execute(next(pending, f"SELECT {user}"))\n', ((CRITICAL, 3),)),
            ('safe-default', '    pending = ("SELECT 1" for item in [])\n    cursor.execute(next(pending, "SELECT 2"))\n', ()),
            ('late-value', '    query = "SELECT 1"\n    pending = (query for item in [1])\n    query = f"SELECT {user}"\n    cursor.execute(next(pending))\n', ((CRITICAL, 5),)),
            ('captured-value', '    query = f"SELECT {user}"\n    pending = (item for item in [query])\n    query = "SELECT 1"\n    cursor.execute(next(pending))\n', ((CRITICAL, 5),)),
            ('filtered-value', '    pending = (f"SELECT {user}" for item in [1] if False)\n    cursor.execute(next(pending, "SELECT 1"))\n', ()),
            ('parser-index', '    index = next((i for i in range(len(rows)) if rows[i].value == "="), None)\n    return index\n', ()),
        )
        for name, body, expected in cases:
            with self.subTest(case=name):
                self.inspect('next-' + name, program(body), expected)

    def test_next_projection_refuses_unmodeled_effects(self):
        bodies = (
            '    pending = ((query := f"SELECT {user}") for item in rows)\n    next(pending, None)\n',
            '    pending = (cursor.execute(f"SELECT {user}") for item in rows)\n    next(pending, None)\n',
            '    pending = (f"SELECT {user}" for item in rows)\n    next(pending)\n    list(pending)\n',
            '    pending = (f"SELECT {user}" for item in rows)\n    next(pending)\n    next(pending)\n',
            '    pending = (f"SELECT {user}" for item in rows)\n    next = unknown\n    next(pending)\n',
            '    pending = (f"SELECT {user}" for item in rows)\n    alias = pending\n    next(pending)\n    tuple(alias)\n',
            '    other = (f"SELECT {user}" for item in rows)\n    pending = (list(other) for item in [1])\n    next(pending)\n',
        )
        for index, body in enumerate(bodies):
            with self.subTest(case=index):
                path = self.artifacts / f'next-boundary-{index}.py'
                path.write_text(program(body), encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator|next projection'):
                    list(detector.find([path]))

    def test_real_sqlite_next_projection(self):
        from contextlib import closing
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        witnesses = (
            ('selected-unsafe', f'next((query for query in [{unsafe}]), {safe})', 2, ((CRITICAL, 2),)),
            ('selected-safe', f'next((query for query in [{safe}]), {safe})', 1, ()),
            ('empty-default-unsafe', f'next((query for query in []), {unsafe})', 2, ((CRITICAL, 2),)),
            ('empty-default-safe', f'next((query for query in []), {safe})', 1, ()),
        )
        for name, expression, rows, expected in witnesses:
            with self.subTest(case=name):
                source = program(f'    return cursor.execute({expression}).fetchone()[0]\n')
                namespace = {}
                exec(compile(source, '<test-authored-next>', 'exec'), namespace)
                with closing(sqlite3.connect(':memory:')) as connection:
                    connection.execute('CREATE TABLE users(name TEXT)')
                    connection.executemany('INSERT INTO users VALUES (?)', [('alice',), ('bob',)])
                    actual = namespace['run'](connection.cursor(), None, "' OR 1=1 --", [])
                self.assertEqual(actual, rows)
                self.inspect('sqlite-next-' + name, source, expected)

    def test_next_eager_default_and_validation_order(self):
        cases = (
            ('late-validator', 'pending = (validate_sql_identifier(user) if item else "id" for item in [0, 1])\nnext(pending)\ncursor.execute(f"SELECT {user}")', CRITICAL),
            ('first-validator', 'pending = (validate_sql_identifier(user) for item in [1])\nnext(pending)\ncursor.execute(f"SELECT {user}")', CRITICAL),
            ('eager-default-validates', 'pending = ("id" for item in [1])\nnext(pending, validate_sql_identifier(user))\ncursor.execute(f"SELECT {user}")', WARNING),
            ('caught-default-validation', 'pending = ("id" for item in [1])\ntry:\n    next(pending, validate_sql_identifier(user))\nexcept ValueError:\n    pass\ncursor.execute(f"SELECT {user}")', CRITICAL),
            ('default-rebind-before-consumption', 'query = "SELECT 1"\npending = (query for item in [1])\nchosen = next(pending, (query := f"SELECT {user}"))\ncursor.execute(chosen)', CRITICAL),
            ('closed-default', 'pending = ("SELECT 1" for item in [1])\npending.close()\ncursor.execute(next(pending, f"SELECT {user}"))', CRITICAL),
            ('exhausted-default', 'pending = ("SELECT 1" for item in [])\nlist(pending)\ncursor.execute(next(pending, f"SELECT {user}"))', CRITICAL),
        )
        import textwrap
        for name, body, rule in cases:
            with self.subTest(case=name):
                source = program(textwrap.indent(body, '    ') + '\n')
                path = self.artifacts / ('next-order-' + name + '.py')
                path.write_text(source, encoding='utf-8')
                with patch.dict(os.environ, {detector.SANITIZER_ENV: 'validate_sql_identifier'}):
                    findings = list(detector.find([path]))
                self.assertEqual([(hit[0], hit[2]) for hit in findings],
                                 [(rule, len(source.splitlines()))], source)

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
                    'gen-alias-shares-exhaustion', 'next-projection-critical',
                    'next-default-critical', 'next-default-static', 'next-late-validation'}
        next_controls = (
            ('next-projection-critical', '    pending = (f"SELECT {user}" for item in [1])\n    cursor.execute(next(pending))\n', ((CRITICAL, 3),)),
            ('next-default-critical', '    pending = ("SELECT 1" for item in [])\n    cursor.execute(next(pending, f"SELECT {user}"))\n', ((CRITICAL, 3),)),
            ('next-default-static', '    pending = ("SELECT 1" for item in [])\n    cursor.execute(next(pending, "SELECT 2"))\n', ()),
            ('next-late-validation', '    pending = (validate_sql_identifier(user) if item else "id" for item in [0, 1])\n    next(pending)\n    cursor.execute(f"SELECT {user}")\n', ((CRITICAL, 4),)),
        )
        for name, body, expected in CASES + GENERATOR_CASES + next_controls:
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


class SQLValidationFlow(unittest.TestCase):
    """A configured validator must protect every path to this exact value.

    Contract: validate_sql_identifier raises on invalid input; it does not
    sanitize a different value, an unexecuted branch, or a later assignment.
    The wrapper cases use that same contract, not another scanner as oracle.
    """

    VALIDATOR = 'validate_sql_identifier'
    CASES = (
        ('direct', 'validate_sql_identifier(column)\ncursor.execute(f"SELECT {column}")', WARNING),
        ('same-line', 'validate_sql_identifier(column); cursor.execute(f"SELECT {column}")', WARNING),
        ('conditional', 'if flag:\n    validate_sql_identifier(column)\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('false-branch', 'if False:\n    validate_sql_identifier(column)\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('both-arms', 'if flag:\n    validate_sql_identifier(column)\nelse:\n    validate_sql_identifier(column)\ncursor.execute(f"SELECT {column}")', WARNING),
        ('early-return', 'if flag:\n    return\nvalidate_sql_identifier(column)\ncursor.execute(f"SELECT {column}")', WARNING),
        ('wrong-value', 'validate_sql_identifier(other)\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('after-sink', 'cursor.execute(f"SELECT {column}")\nvalidate_sql_identifier(column)', CRITICAL),
        ('rebound', 'validate_sql_identifier(column)\ncolumn = other\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('rebound-during-validation', 'validate_sql_identifier(column, (column := other))\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('rebound-before-validation', 'validate_sql_identifier((column := other))\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('attribute-mutated-during-validation', 'validate_sql_identifier(config.column, config.refresh())\ncursor.execute(f"SELECT {config.column}")', CRITICAL),
        ('literal-overwrite', 'validate_sql_identifier(column)\ncolumn = "id"\ncursor.execute(f"SELECT {column}")', None),
        ('attribute-replaced', 'validate_sql_identifier(config.column)\nconfig.column = other\ncursor.execute(f"SELECT {config.column}")', CRITICAL),
        ('root-replaced', 'validate_sql_identifier(config.column)\nconfig = other\ncursor.execute(f"SELECT {config.column}")', CRITICAL),
        ('attribute-alias-write', 'alias = config\nvalidate_sql_identifier(config.column)\nalias.column = other\ncursor.execute(f"SELECT {config.column}")', CRITICAL),
        ('call-can-mutate', 'validate_sql_identifier(config.column)\nmutate(config)\ncursor.execute(f"SELECT {config.column}")', CRITICAL),
        ('method-can-mutate', 'validate_sql_identifier(config.column)\nconfig.refresh()\ncursor.execute(f"SELECT {config.column}")', CRITICAL),
        ('failed-validator-caught', 'try:\n    validate_sql_identifier(column)\nexcept ValueError:\n    pass\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('failed-validator-exits', 'try:\n    validate_sql_identifier(column)\nexcept ValueError:\n    return\ncursor.execute(f"SELECT {column}")', WARNING),
        ('finally-validates', 'try:\n    work()\nexcept ValueError:\n    pass\nfinally:\n    validate_sql_identifier(column)\ncursor.execute(f"SELECT {column}")', WARNING),
        ('zero-trip', 'for item in []:\n    validate_sql_identifier(column)\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('one-trip', 'for item in [1]:\n    validate_sql_identifier(column)\ncursor.execute(f"SELECT {column}")', WARNING),
        ('unknown-trip', 'for item in rows:\n    validate_sql_identifier(column)\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('captured-before-validation', 'query = f"SELECT {column}"\nvalidate_sql_identifier(column)\ncursor.execute(query)', CRITICAL),
        ('captured-after-validation', 'validate_sql_identifier(column)\nquery = f"SELECT {column}"\ncolumn = other\ncursor.execute(query)', WARNING),
        ('nested-body-not-executed', 'def unused():\n    validate_sql_identifier(column)\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('comprehension-local-not-proof', 'unused = [validate_sql_identifier(column) for column in ["id"]]\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('lazy-unused-validation', 'pending = (validate_sql_identifier(column) for item in [1])\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('lazy-drained-validation', 'pending = (validate_sql_identifier(column) for item in [1])\nlist(pending)\ncursor.execute(f"SELECT {column}")', WARNING),
        ('lazy-empty-validation', 'pending = (validate_sql_identifier(column) for item in [])\nlist(pending)\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('lazy-caught-failure', 'pending = (validate_sql_identifier(column) for item in [1])\ntry:\n    list(pending)\nexcept ValueError:\n    pass\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('lazy-unknown-count', 'pending = (validate_sql_identifier(column) for item in rows)\nlist(pending)\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('lazy-conditional-drain', 'pending = (validate_sql_identifier(column) for item in [1])\nif flag:\n    list(pending)\ncursor.execute(f"SELECT {column}")', CRITICAL),
        ('lazy-both-drains', 'pending = (validate_sql_identifier(column) for item in [1])\nif flag:\n    list(pending)\nelse:\n    tuple(pending)\ncursor.execute(f"SELECT {column}")', WARNING),
        ('lazy-alias-not-revalidation', 'pending = (validate_sql_identifier(column) for item in [1])\nalias = pending\nlist(pending)\ncolumn = other\nlist(alias)\ncursor.execute(f"SELECT {column}")', CRITICAL),
    )
    WRAPPERS = (
        ('straight', 'validate_sql_identifier(value)', WARNING),
        ('conditional', 'if flag:\n    validate_sql_identifier(value)', CRITICAL),
        ('both-arms', 'if flag:\n    validate_sql_identifier(value)\nelse:\n    validate_sql_identifier(value)', WARNING),
        ('return-before', 'return\nvalidate_sql_identifier(value)', CRITICAL),
        ('return-path', 'if flag:\n    return\nvalidate_sql_identifier(value)', CRITICAL),
        ('raise-path', 'if flag:\n    raise ValueError()\nvalidate_sql_identifier(value)', WARNING),
        ('rebound-parameter', 'value = "id"\nvalidate_sql_identifier(value)', CRITICAL),
        ('caught-validation', 'try:\n    validate_sql_identifier(value)\nexcept ValueError:\n    pass', CRITICAL),
        ('zero-trip', 'for item in []:\n    validate_sql_identifier(value)', CRITICAL),
        ('finally', 'try:\n    work()\nfinally:\n    validate_sql_identifier(value)', WARNING),
        ('lazy-unconsumed', 'return (validate_sql_identifier(value) for item in [1])', CRITICAL),
        ('lazy-drained', 'pending = (validate_sql_identifier(value) for item in [1])\nlist(pending)', WARNING),
        ('lazy-empty', 'pending = (validate_sql_identifier(value) for item in [])\nlist(pending)', CRITICAL),
        ('lazy-caught', 'pending = (validate_sql_identifier(value) for item in [1])\ntry:\n    list(pending)\nexcept ValueError:\n    pass', CRITICAL),
    )

    @classmethod
    def setUpClass(cls):
        artifacts = ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        cls.artifacts = Path(tempfile.mkdtemp(prefix='sql-validation-flow-', dir=artifacts))

    @classmethod
    def programs(cls):
        import textwrap
        for name, body, rule in cls.CASES:
            source = ('def run(cursor, column, other, config, flag, rows):\n' +
                      textwrap.indent(body, '    ') + '\n')
            yield name, source, rule
        for name, body, rule in cls.WRAPPERS:
            source = ('def check(value, flag):\n' + textwrap.indent(body, '    ') + '\n' +
                      'def run(cursor, column, flag):\n    check(column, flag)\n'
                      '    cursor.execute(f"SELECT {column}")\n')
            yield 'wrapper-' + name, source, rule

    def test_validation_paths(self):
        for name, source, expected_rule in self.programs():
            with self.subTest(case=name):
                path = self.artifacts / (name + '.py')
                path.write_text(source, encoding='utf-8')
                expected = [] if expected_rule is None else [(expected_rule, next(
                    n for n, line in enumerate(source.splitlines(), 1) if 'cursor.execute(' in line))]
                started = time.perf_counter()
                with patch.dict(os.environ, {detector.SANITIZER_ENV: self.VALIDATOR}):
                    findings = list(detector.find([path]))
                actual = [(rule, line) for rule, _, line, _, _ in findings]
                path.with_suffix('.json').write_text(json.dumps({
                    'case': name, 'expected': expected, 'actual': actual,
                    'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                    'detector_sha256': hashlib.sha256(Path(detector.__file__).read_bytes()).hexdigest(),
                    'elapsed_seconds': time.perf_counter() - started, 'python': sys.version,
                }, indent=2) + '\n', encoding='utf-8')
                self.assertEqual(actual, expected, source)

    def test_sqlite_validation_witnesses(self):
        import textwrap
        cases = (
            ('skipped', 'if flag:\n    validate_sql_identifier(column)', False, "' OR 1=1 --", 2, CRITICAL),
            ('caught', 'try:\n    validate_sql_identifier(column)\nexcept ValueError:\n    pass', False, "' OR 1=1 --", 2, CRITICAL),
            ('reassigned', 'validate_sql_identifier(column)\ncolumn = other', False, 'alice', 2, CRITICAL),
            ('successful', 'validate_sql_identifier(column)', False, 'alice', 1, WARNING),
            ('both-paths', 'if flag:\n    validate_sql_identifier(column)\nelse:\n    validate_sql_identifier(column)', False, 'alice', 1, WARNING),
            ('return-on-failure', 'try:\n    validate_sql_identifier(column)\nexcept ValueError:\n    return -1', False, "' OR 1=1 --", -1, WARNING),
        )
        def validate_sql_identifier(value):
            if value not in {'alice', 'bob'}:
                raise ValueError('identifier not allowed')
        for name, body, flag, value, count, rule in cases:
            with self.subTest(case=name):
                source = ('def run(cursor, column, other, flag):\n' + textwrap.indent(body, '    ') +
                          '\n    return cursor.execute(f"SELECT count(*) FROM users WHERE name = \'{column}\'").fetchone()[0]\n')
                namespace = {'validate_sql_identifier': validate_sql_identifier, 'ValueError': ValueError}
                exec(compile(source, name, 'exec'), namespace)
                connection = sqlite3.connect(':memory:')
                try:
                    cursor = connection.cursor()
                    cursor.execute('CREATE TABLE users (name TEXT)')
                    cursor.executemany('INSERT INTO users VALUES (?)', [('alice',), ('bob',)])
                    actual_count = namespace['run'](cursor, value, "' OR 1=1 --", flag)
                finally:
                    connection.close()
                path = self.artifacts / ('sqlite-' + name + '.py')
                path.write_text(source, encoding='utf-8')
                with patch.dict(os.environ, {detector.SANITIZER_ENV: self.VALIDATOR}):
                    findings = list(detector.find([path]))
                (self.artifacts / ('sqlite-' + name + '.json')).write_text(json.dumps({
                    'case': name, 'expected_rows': count, 'actual_rows': actual_count,
                    'expected_rule': rule, 'actual_rules': [item[0] for item in findings],
                    'sqlite_version': sqlite3.sqlite_version, 'python': sys.version,
                }, indent=2) + '\n', encoding='utf-8')
                self.assertEqual(actual_count, count)
                self.assertEqual([item[0] for item in findings], [rule])


class SQLValidationBindings(unittest.TestCase):
    """Trusted spelling must resolve to the configured callable, not a suffix."""

    CASES = (
        ('import-module', 'import psycopg.sql\ndef run(cursor, value):\n    cursor.execute(f"SELECT {psycopg.sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', None),
        ('import-submodule', 'from psycopg import sql\ndef run(cursor, value):\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', None),
        ('import-alias', 'import psycopg.sql as query_sql\ndef run(cursor, value):\n    cursor.execute(f"SELECT {query_sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', None),
        ('import-function-alias', 'from psycopg.sql import Identifier as quoted\ndef run(cursor, value):\n    cursor.execute(f"SELECT {quoted(value)}")\n', 'psycopg.sql.Identifier', None),
        ('module-binding-alias', 'from psycopg import sql\nquery_sql = sql\ndef run(cursor, value):\n    cursor.execute(f"SELECT {query_sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', None),
        ('callable-binding-alias', 'from psycopg import sql\nquoted = sql.Identifier\ndef run(cursor, value):\n    cursor.execute(f"SELECT {quoted(value)}")\n', 'psycopg.sql.Identifier', None),
        ('alias-module-escape', 'from psycopg import sql\nother = sql\nconfigure(other)\ndef run(cursor, value):\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('annotation-exec', 'from psycopg import sql\ndef change(value: exec(code)):\n    pass\ndef run(cursor, value):\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('unrelated-import', 'from evil import sql\ndef run(cursor, value):\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('unrelated-receiver', 'def run(cursor, value, arbitrary):\n    cursor.execute(f"SELECT {arbitrary.Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('bare-parameter', 'def run(cursor, value, Identifier):\n    cursor.execute(f"SELECT {Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('module-shadow', 'from psycopg import sql\ndef run(cursor, value, sql):\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('alias-shadow', 'from psycopg.sql import Identifier as quoted\ndef run(cursor, value, quoted):\n    cursor.execute(f"SELECT {quoted(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('alias-reassigned', 'from psycopg.sql import Identifier as quoted\ndef run(cursor, value, replacement):\n    quoted = replacement\n    cursor.execute(f"SELECT {quoted(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('module-reassigned', 'from psycopg import sql\nsql = replacement\ndef run(cursor, value):\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('member-replaced', 'from psycopg import sql\nsql.Identifier = replacement\ndef run(cursor, value):\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('module-escaped', 'from psycopg import sql\nconfigure(sql)\ndef run(cursor, value):\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('relative-import-not-absolute', 'from .psycopg import sql\ndef run(cursor, value):\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('bare-contract', 'def run(cursor, value):\n    cursor.execute(f"SELECT {quote_ident(value)}")\n', 'quote_ident', None),
        ('bare-contract-shadowed', 'def run(cursor, value, quote_ident):\n    cursor.execute(f"SELECT {quote_ident(value)}")\n', 'quote_ident', CRITICAL),
        ('bare-contract-unrelated-method', 'def run(cursor, value, arbitrary):\n    cursor.execute(f"SELECT {arbitrary.quote_ident(value)}")\n', 'quote_ident', CRITICAL),
        ('namespace-exec', 'from psycopg import sql\nexec(setup)\ndef run(cursor, value):\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('global-rebinding', 'from psycopg import sql\ndef replace():\n    global sql\n    sql = replacement\ndef run(cursor, value):\n    replace()\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', CRITICAL),
        ('comp-shadow', 'from psycopg import sql\ndef run(cursor, value, replacements):\n    queries = [f"SELECT {sql.Identifier(value)}" for sql in replacements]\n    for query in queries:\n        cursor.execute(query)\n', 'psycopg.sql.Identifier', CRITICAL),
        ('comp-import-retained-outside', 'from psycopg import sql\ndef run(cursor, value, replacements):\n    ignored = [sql for sql in replacements]\n    cursor.execute(f"SELECT {sql.Identifier(value)}")\n', 'psycopg.sql.Identifier', None),
        ('helper-parameter-shadow', 'def check(value):\n    validate_sql_identifier(value)\ndef run(cursor, value, check):\n    check(value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', CRITICAL),
        ('helper-rebound', 'def check(value):\n    validate_sql_identifier(value)\ndef run(cursor, value, replacement):\n    check = replacement\n    check(value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', CRITICAL),
        ('helper-foreign-receiver', 'def check(value):\n    validate_sql_identifier(value)\ndef run(cursor, value, arbitrary):\n    arbitrary.check(value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', CRITICAL),
        ('helper-decorated', '@replace_helper\ndef check(value):\n    validate_sql_identifier(value)\ndef run(cursor, value):\n    check(value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', CRITICAL),
        ('helper-async-not-awaited', 'async def check(value):\n    validate_sql_identifier(value)\ndef run(cursor, value):\n    check(value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', CRITICAL),
        ('helper-generator-not-consumed', 'def check(value):\n    validate_sql_identifier(value)\n    yield value\ndef run(cursor, value):\n    check(value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', CRITICAL),
        ('helper-classmethod', 'class Writer:\n    @classmethod\n    def check(cls, value):\n        validate_sql_identifier(value)\n    @classmethod\n    def run(cls, cursor, value):\n        cls.check(value)\n        cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', WARNING),
        ('helper-staticmethod', 'class Writer:\n    @staticmethod\n    def check(value):\n        validate_sql_identifier(value)\ndef run(cursor, value):\n    Writer.check(value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', WARNING),
        ('helper-unbound-method', 'class Writer:\n    def check(self, value):\n        validate_sql_identifier(value)\ndef run(cursor, value, instance):\n    Writer.check(instance, value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', WARNING),
        ('helper-instance-method', 'class Writer:\n    def check(self, value):\n        validate_sql_identifier(value)\n    def run(self, cursor, value):\n        self.check(value)\n        cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', WARNING),
        ('helper-same-name-distinct-owner', 'class Good:\n    @staticmethod\n    def check(value):\n        validate_sql_identifier(value)\nclass Bad:\n    @staticmethod\n    def check(value):\n        return value\ndef run(cursor, value):\n    Good.check(value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', WARNING),
        ('helper-foreign-same-name', 'class Good:\n    @staticmethod\n    def check(value):\n        validate_sql_identifier(value)\nclass Bad:\n    @staticmethod\n    def check(value):\n        return value\ndef run(cursor, value):\n    Bad.check(value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', CRITICAL),
        ('helper-lambda-shadow', 'def check(value):\n    validate_sql_identifier(value)\ndef run(cursor, value):\n    check = lambda item: item\n    check(value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', CRITICAL),
        ('helper-binding-alias', 'def check(value):\n    validate_sql_identifier(value)\nverify = check\ndef run(cursor, value):\n    verify(value)\n    cursor.execute(f"SELECT {value}")\n', 'validate_sql_identifier', WARNING),
    )

    @classmethod
    def setUpClass(cls):
        artifacts = ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        cls.artifacts = Path(tempfile.mkdtemp(prefix='sql-validation-bindings-', dir=artifacts))

    def test_binding_verified_validation(self):
        for name, source, configuration, rule in self.CASES:
            with self.subTest(case=name):
                path = self.artifacts / (name + '.py')
                path.write_text(source, encoding='utf-8')
                expected = [] if rule is None else [(rule, next(
                    n for n, line in enumerate(source.splitlines(), 1) if 'cursor.execute(' in line))]
                with patch.dict(os.environ, {detector.SANITIZER_ENV: configuration}):
                    actual = [(r, line) for r, _, line, _, _ in detector.find([path])]
                path.with_suffix('.json').write_text(json.dumps({
                    'case': name, 'configuration': configuration, 'expected': expected, 'actual': actual,
                    'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                    'detector_sha256': hashlib.sha256(Path(detector.__file__).read_bytes()).hexdigest(),
                    'python': sys.version,
                }, indent=2) + '\n', encoding='utf-8')
                self.assertEqual(actual, expected, source)

    def test_sqlite_callable_identity(self):
        suffix = '    return cursor.execute(f"SELECT count(*) FROM users WHERE name = \'{value}\'").fetchone()[0]\n'
        header = 'def run(cursor, value, arbitrary):\n'
        cases = (
            ('foreign-Identifier', header + '    value = arbitrary.Identifier(value)\n' + suffix,
             'psycopg.sql.Identifier', "' OR 1=1 --", 2, CRITICAL),
            ('shadowed-quote', header + '    quote_ident = arbitrary.Identifier\n    value = quote_ident(value)\n' + suffix,
             'quote_ident', "' OR 1=1 --", 2, CRITICAL),
            ('wrong-helper-receiver', 'def check(value):\n    validate_sql_identifier(value)\n' +
             header + '    arbitrary.check(value)\n' + suffix,
             'validate_sql_identifier', "' OR 1=1 --", 2, CRITICAL),
            ('decorator-replacement', 'def replacement(function):\n    return lambda value: value\n' +
             '@replacement\ndef check(value):\n    validate_sql_identifier(value)\n' +
             header + '    check(value)\n' + suffix, 'validate_sql_identifier', "' OR 1=1 --", 2, CRITICAL),
            ('coroutine-not-executed', 'async def check(value):\n    validate_sql_identifier(value)\n' +
             header + '    pending = check(value)\n    pending.close()\n' + suffix,
             'validate_sql_identifier', "' OR 1=1 --", 2, CRITICAL),
            ('generator-not-executed', 'def check(value):\n    validate_sql_identifier(value)\n    yield value\n' +
             header + '    pending = check(value)\n    pending.close()\n' + suffix,
             'validate_sql_identifier', "' OR 1=1 --", 2, CRITICAL),
            ('real-static-helper', 'class Writer:\n    @staticmethod\n    def check(value):\n        validate_sql_identifier(value)\n' +
             header + '    Writer.check(value)\n' + suffix, 'validate_sql_identifier', 'alice', 1, WARNING),
        )
        class Arbitrary:
            def Identifier(self, value):
                return value

            def check(self, value):
                return value

        def validate_sql_identifier(value):
            if value not in {'alice', 'bob'}:
                raise ValueError('identifier not allowed')

        for name, source, configuration, value, count, rule in cases:
            with self.subTest(case=name):
                namespace = {'validate_sql_identifier': validate_sql_identifier}
                exec(compile(source, name, 'exec'), namespace)
                connection = sqlite3.connect(':memory:')
                try:
                    cursor = connection.cursor()
                    cursor.execute('CREATE TABLE users (name TEXT)')
                    cursor.executemany('INSERT INTO users VALUES (?)', [('alice',), ('bob',)])
                    actual_count = namespace['run'](cursor, value, Arbitrary())
                finally:
                    connection.close()
                path = self.artifacts / ('sqlite-' + name + '.py')
                path.write_text(source, encoding='utf-8')
                with patch.dict(os.environ, {detector.SANITIZER_ENV: configuration}):
                    actual = [(r, n) for r, _, n, _, _ in detector.find([path])]
                expected = [(rule, next(n for n, line in enumerate(source.splitlines(), 1)
                                        if 'cursor.execute(' in line))]
                path.with_suffix('.json').write_text(json.dumps({
                    'case': name, 'configuration': configuration, 'expected_rows': count,
                    'actual_rows': actual_count, 'expected_findings': expected, 'actual_findings': actual,
                    'sqlite_version': sqlite3.sqlite_version, 'python': sys.version,
                }, indent=2) + '\n', encoding='utf-8')
                self.assertEqual(actual_count, count)
                self.assertEqual(actual, expected)

    @unittest.skipUnless((ROOT / 'ubs').is_file() and (ROOT / 'modules/ubs-python.sh').is_file(),
                         'real CLI requires a full checkout')
    def test_real_cli_validation_contract(self):
        selected = [(name, source, SQLValidationFlow.VALIDATOR, rule)
                    for name, source, rule in SQLValidationFlow.programs()
                    if name in {'conditional', 'failed-validator-caught', 'direct', 'literal-overwrite'}]
        selected += [case for case in self.CASES if case[0] in {'import-function-alias', 'unrelated-receiver'}]
        for name, source, configuration, rule in selected:
            expected = [] if rule is None else [(rule, next(n for n, line in enumerate(source.splitlines(), 1)
                                                          if 'cursor.execute(' in line))]
            for entry in ('modules/ubs-python.sh', 'ubs'):
                for fmt in ('json', 'sarif'):
                    with self.subTest(case=name, entry=entry, format=fmt):
                        folder = self.artifacts / (name + '-' + entry.replace('/', '-') + '-' + fmt)
                        folder.mkdir()
                        path = folder / 'case.py'
                        path.write_text(source, encoding='utf-8')
                        for directory in ('home', 'cache', 'tmp'):
                            (folder / directory).mkdir()
                        env = {key: value for key, value in os.environ.items() if not key.startswith('UBS_')}
                        env.update(HOME=str(folder / 'home'), XDG_CACHE_HOME=str(folder / 'cache'),
                                   TMPDIR=str(folder / 'tmp'), UBS_KEEP_TEMP='1', UBS_NO_AUTO_UPDATE='1',
                                   PYTHONDONTWRITEBYTECODE='1', NO_COLOR='1', ENABLE_UV_TOOLS='0',
                                   UBS_PY_SQL_SANITIZERS=configuration)
                        skip = ','.join(str(n) for n in range(1, 24) if n != 7)
                        command = ['bash', str(ROOT / entry), '--ci', '--no-color', '--fail-on-warning',
                                   '--format=' + fmt, '--skip=' + skip]
                        command += ['--only=python'] if entry == 'ubs' else ['--no-uv']
                        command.append(str(path))
                        started = time.perf_counter()
                        try:
                            result = subprocess.run(command, cwd=folder, env=env, capture_output=True,
                                                    text=True, timeout=120, check=False)
                        except subprocess.TimeoutExpired as exc:
                            for stream in ('stdout', 'stderr'):
                                content = getattr(exc, stream) or b''
                                if isinstance(content, str):
                                    content = content.encode('utf-8')
                                (folder / (stream + '.log')).write_bytes(content)
                            self.fail(f'CLI timeout: {command}; evidence: {folder}')
                        (folder / 'stdout.log').write_text(result.stdout, encoding='utf-8')
                        (folder / 'stderr.log').write_text(result.stderr, encoding='utf-8')
                        (folder / 'run.json').write_text(json.dumps({
                            'command': command, 'exit': result.returncode, 'configuration': configuration,
                            'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                            'detector_sha256': hashlib.sha256(Path(detector.__file__).read_bytes()).hexdigest(),
                            'entry_sha256': hashlib.sha256((ROOT / entry).read_bytes()).hexdigest(),
                            'elapsed_seconds': time.perf_counter() - started,
                        }, indent=2) + '\n', encoding='utf-8')
                        self.assertEqual(result.returncode, 1 if rule else 0, result.stderr)
                        try:
                            doc = json.loads(result.stdout)
                        except ValueError as exc:
                            self.fail(f'Malformed CLI output: {exc}; evidence: {folder}')
                        actual = []
                        if fmt == 'json':
                            scans = doc['scanners'] if entry == 'ubs' else [doc]
                            self.assertEqual(len(scans), 1)
                            scan = scans[0]
                            self.assertEqual((scan['status'], scan['files']), ('ok', 1))
                            for severity in ('critical', 'warning', 'info'):
                                self.assertEqual(scan[severity], sum(f['count'] for f in scan['findings']
                                                                    if f['severity'] == severity))
                            for finding in scan['findings']:
                                found_rule = finding.get('rule_id', finding.get('rule'))
                                if found_rule in {CRITICAL, WARNING}:
                                    self.assertEqual(finding['count'], len(finding['samples']))
                                    for sample in finding['samples']:
                                        self.assertEqual(Path(sample['file']).name, path.name)
                                        actual.append((found_rule, sample['line']))
                        else:
                            self.assertEqual(doc['version'], '2.1.0')
                            for run in doc['runs']:
                                for finding in run.get('results', []):
                                    if finding['ruleId'] in {CRITICAL, WARNING}:
                                        place = finding['locations'][0]['physicalLocation']
                                        self.assertEqual(Path(unquote(place['artifactLocation']['uri'])).name, path.name)
                                        self.assertEqual(place['region']['startColumn'], 1)
                                        actual.append((finding['ruleId'], place['region']['startLine']))
                        self.assertEqual(sorted(actual), sorted(expected), folder)


if __name__ == '__main__':
    unittest.main(verbosity=2)
