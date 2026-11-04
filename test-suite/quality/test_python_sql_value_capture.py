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
    ('match-branch-sql', '    query = "SELECT 1"\n    match user:\n        case _ if user:\n            query = f"SELECT {user}"\n        case _:\n            query = "SELECT 1"\n    cursor.execute(query)\n', ((CRITICAL, 8),)),
    ('match-captured-sql', '    match user:\n        case captured:\n            cursor.execute(f"SELECT {captured}")\n', ((CRITICAL, 4),)),
    ('match-false-guard', '    match user:\n        case captured if False:\n            cursor.execute(f"SELECT {user}")\n        case _:\n            cursor.execute("SELECT 1")\n', ()),
    ('match-sequence-sql', '    parts = ("SELECT ", user)\n    match parts:\n        case (prefix, body):\n            cursor.execute(prefix + body)\n', ((CRITICAL, 5),)),
    ('list-truth-test', '    queries = []\n    empty = not queries\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 5),)),
    ('list-read-only-helper', '    def examine(values):\n        for value in reversed(values):\n            pass\n    queries = []\n    examine(queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 8),)),
    ('list-reversed-read', '    queries = ["SELECT 1"]\n    for query in reversed(queries):\n        cursor.execute(query)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[1])\n', ((CRITICAL, 6),)),
    ('list-closure-append', '    queries = []\n    def add(value):\n        queries.append(value)\n    add(f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 6),)),
    ('closure-cell-copy-sql', '    queries = []\n    query = "SELECT 1"\n    def add(value):\n        nonlocal query\n        query = value\n        queries.append(value)\n        snapshot = tuple(item for item in queries[:])\n        return snapshot\n    add(f"SELECT {user}")\n    cursor.execute(query)\n', ((CRITICAL, 11),)),
    ('closure-cell-copy-clean', '    queries = []\n    query = "SELECT 1"\n    def add(value):\n        nonlocal query\n        query = value\n        queries.append(value)\n        snapshot = tuple(item for item in queries[:])\n        return snapshot\n    add("SELECT 2")\n    cursor.execute(query)\n', ()),
    ('list-immediate-predicate', '    queries = []\n    def add(value):\n        queries.append(value)\n    present = any(query == "SELECT 1" for query in queries)\n    add(f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 7),)),
    ('list-pop-then-extend', '    queries = ["SELECT 1"]\n    queries.pop()\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 5),)),
    ('list-insert-sql', '    queries = ["SELECT 1"]\n    queries.insert(0, f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('list-setitem-sql', '    queries = ["SELECT 1"]\n    queries.__setitem__(0, f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('list-item-sql', '    queries = [""]\n    queries[0] = f"SELECT {user}"\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('list-ann-item-sql', '    queries = [""]\n    queries[0]: str = f"SELECT {user}"\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('list-aug-item-sql', '    queries = [""]\n    queries[0] += f"SELECT {user}"\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('list-slice-sql', '    queries = [""]\n    queries[:] = [f"SELECT {user}"]\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('list-for-target-sql', '    queries = [""]\n    for queries[0] in [f"SELECT {user}"]:\n        pass\n    cursor.execute(queries[0])\n', ((CRITICAL, 5),)),
    ('list-comp-target-sql', '    queries = [""]\n    unused = [None for queries[0] in [f"SELECT {user}"]]\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('list-parallel-target-sql', '    queries = [""]\n    index, queries[index] = 0, f"SELECT {user}"\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('string-slice-sql', '    queries = []\n    queries[:] = "".join([f"SELECT {user}"])\n    cursor.execute("".join(queries))\n', ((CRITICAL, 4),)),
    ('generator-string-slice-sql', '    queries = []\n    queries[:] = "".join(query for query in [f"SELECT {user}"])\n    cursor.execute("".join(queries))\n', ((CRITICAL, 4),)),
    ('recursive-string-slice-sql', '    def render(value, depth=0):\n        if depth:\n            value = render(value, depth - 1)\n        return "".join([value])\n    queries = []\n    queries[:] = render(f"SELECT {user}", 1)\n    cursor.execute("".join(queries))\n', ((CRITICAL, 8),)),
    ('numeric-length-index-sql', '    queries = ["SELECT 1"]\n    queries[len([0]) - 1] = f"SELECT {user}"\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('numeric-repetition-slice-sql', '    queries = []\n    queries[:] = [f"SELECT {user}"] * (3 - 2)\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('numeric-repeated-owner-sql', '    queries = ["SELECT 1"] * len([0])\n    queries[0] = f"SELECT {user}"\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('numeric-repeated-owner-clean', '    queries = ["SELECT 1"] * len([0])\n    queries[0] = "SELECT 2"\n    cursor.execute(queries[0])\n', ()),
    ('numeric-enumerate-start-sql', '    queries = ["SELECT 1"]\n    for index, unused in enumerate([0], start=1):\n        queries[index - 1] = f"SELECT {user}"\n    cursor.execute(queries[0])\n', ((CRITICAL, 5),)),
    ('sequence-index-sql', '    indices = (0,)\n    queries = ["SELECT 1"]\n    queries[indices[0]] = f"SELECT {user}"\n    cursor.execute(queries[0])\n', ((CRITICAL, 5),)),
    ('sequence-slice-sql', '    values = [f"SELECT {user}"]\n    queries = []\n    queries[:] = values[:]\n    cursor.execute(queries[0])\n', ((CRITICAL, 5),)),
    ('sequence-slice-clean', '    values = ["SELECT 1"]\n    queries = []\n    queries[:] = values[:]\n    cursor.execute("".join(queries))\n', ()),
    ('sibling-closure-sql', '    queries = []\n    def add(value):\n        queries.append(value)\n    def forward(value):\n        add(value)\n    forward(f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 8),)),
    ('sibling-closure-clean', '    queries = []\n    def add(value):\n        queries.append(value)\n    def forward(value):\n        add(value)\n    forward("SELECT 1")\n    cursor.execute(queries[0])\n', ()),
    ('recursive-return-sql', '    queries = []\n    def render(value, again):\n        if again:\n            return "".join([render(value, False)])\n        queries.append(value)\n        return value\n    query = render(f"SELECT {user}", True)\n    cursor.execute(query)\n', ((CRITICAL, 9),)),
    ('recursive-return-clean', '    queries = []\n    def render(value, again):\n        if again:\n            return "".join([render(value, False)])\n        queries.append(value)\n        return value\n    query = render("SELECT 1", True)\n    cursor.execute(query)\n', ()),
    ('closed-frame-sql', '    frames = [[0, True]]\n    frame = frames[-1]\n    frames.append([0, False])\n    selected = frames.pop()\n    selected[0] += 1\n    frame[0] = selected[0]\n    queries = ["SELECT 1", f"SELECT {user}"]\n    cursor.execute(queries[frame[0]])\n', ((CRITICAL, 9),)),
    ('closed-frame-clean', '    frames = [[0, True]]\n    frame = frames[-1]\n    frames.append([0, False])\n    selected = frames.pop()\n    selected[0] += 1\n    frame[0] = selected[0]\n    queries = ["SELECT 1", "SELECT 2"]\n    cursor.execute(queries[frame[0]])\n', ()),
    ('record-frame-sql', '    frames = [["code", 0]]\n    frame = frames[-1]\n    frame[1] += 1\n    queries = ["SELECT 1", f"SELECT {user}"]\n    cursor.execute(queries[frame[1]])\n', ((CRITICAL, 6),)),
    ('record-frame-clean', '    frames = [["code", 0]]\n    frame = frames[-1]\n    frame[1] += 1\n    queries = ["SELECT 1", "SELECT 2"]\n    cursor.execute(queries[frame[1]])\n', ()),
    ('list-parameter-sql', '    def write(output, value):\n        output.append(value)\n    queries = []\n    write(queries, f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 6),)),
    ('list-parameter-clean', '    def write(output, value):\n        output.append(value)\n    queries = []\n    write(queries, "SELECT 1")\n    cursor.execute(queries[0])\n', ()),
    ('tuple-bounds-sql', '    bounds = []\n    bounds.append((0, 1))\n    queries = ["SELECT 1"]\n    for low, high in bounds:\n        queries[low:high] = [f"SELECT {user}"]\n    cursor.execute("".join(queries))\n', ((CRITICAL, 7),)),
    ('tuple-bounds-clean', '    bounds = []\n    bounds.append((0, 1))\n    queries = ["SELECT 1"]\n    for low, high in bounds:\n        queries[low:high] = ["SELECT 2"]\n    cursor.execute("".join(queries))\n', ()),
    ('regex-bounds-sql', '    import re\n    match = re.search(".", user)\n    bounds = []\n    bounds.append(match.span())\n    queries = ["SELECT 1"]\n    for low, high in bounds:\n        queries[low:high] = [f"SELECT {user}"]\n    cursor.execute("".join(queries))\n', ((CRITICAL, 9),)),
    ('regex-bounds-clean', '    import re\n    match = re.search(".", user)\n    bounds = []\n    bounds.append(match.span())\n    queries = ["SELECT 1"]\n    for low, high in bounds:\n        queries[low:high] = ["SELECT 2"]\n    cursor.execute("".join(queries))\n', ()),
    ('recursive-tuple-shape-sql', '    shape = ()\n    count = 0\n    while count < 2:\n        shape = (shape,)\n        count += 1\n    cursor.execute(f"SELECT count(*) FROM users WHERE name = \'{user}\'")\n', ((CRITICAL, 7),)),
    ('recursive-tuple-shape-clean', '    shape = ()\n    count = 0\n    while count < 2:\n        shape = (shape,)\n        count += 1\n    cursor.execute("SELECT count(*) FROM users WHERE name = \'alice\'")\n', ()),
    ('sibling-cycle-sql', '    queries = []\n    def first(value, depth):\n        if depth:\n            second(value, depth - 1)\n        else:\n            queries.append(value)\n    def second(value, depth):\n        if depth:\n            first(value, depth - 1)\n        else:\n            queries.append(value)\n    first(f"SELECT {user}", 3)\n    cursor.execute(queries[-1])\n', ((CRITICAL, 14),)),
    ('sibling-cycle-clean', '    queries = []\n    def first(value, depth):\n        if depth:\n            second(value, depth - 1)\n        else:\n            queries.append(value)\n    def second(value, depth):\n        if depth:\n            first(value, depth - 1)\n        else:\n            queries.append(value)\n    first("SELECT 1", 3)\n    cursor.execute(queries[-1])\n', ()),
    ('sibling-cycle-return-sql', '    queries = []\n    def first(value, depth):\n        if depth:\n            return second(value, depth - 1)\n        queries.append(None)\n        return value\n    def second(value, depth):\n        if depth:\n            return first(value, depth - 1)\n        queries.append(None)\n        return value\n    selected = first(f"SELECT {user}", 3)\n    cursor.execute(selected)\n', ((CRITICAL, 14),)),
    ('sibling-cycle-return-clean', '    queries = []\n    def first(value, depth):\n        if depth:\n            return second(value, depth - 1)\n        queries.append(None)\n        return value\n    def second(value, depth):\n        if depth:\n            return first(value, depth - 1)\n        queries.append(None)\n        return value\n    selected = first("SELECT 1", 3)\n    cursor.execute(selected)\n', ()),
    ('frame-enumerate-sql', '    import sys\n    namespace = sys._getframe().f_builtins\n    original = namespace.get("enumerate", enumerate)\n    try:\n        namespace["enumerate"] = lambda values: [(user, None)]\n        for index, unused in enumerate([1]):\n            cursor.execute(f"SELECT {index}")\n    finally:\n        namespace["enumerate"] = original\n', ((CRITICAL, 8),)),
    ('computed-frame-enumerate-sql', '    import sys\n    namespace = getattr(getattr(sys, "_get" + "frame")(), "f_" + "builtins")\n    original = namespace.get("enumerate", enumerate)\n    try:\n        namespace["enumerate"] = lambda values: [(user, None)]\n        for index, unused in enumerate([1]):\n            cursor.execute(f"SELECT {index}")\n    finally:\n        namespace["enumerate"] = original\n', ((CRITICAL, 8),)),
    ('aliased-frame-enumerate-sql', '    import sys\n    lookup = getattr\n    namespace = lookup(lookup(sys, "_getframe")(), "f_builtins")\n    original = namespace.get("enumerate", enumerate)\n    try:\n        namespace["enumerate"] = lambda values: [(user, None)]\n        for index, unused in enumerate([1]):\n            cursor.execute(f"SELECT {index}")\n    finally:\n        namespace["enumerate"] = original\n', ((CRITICAL, 9),)),
    ('transitive-frame-enumerate-sql', '    import sys\n    lookup = getattr\n    read = lookup\n    namespace = read(read(sys, "_getframe")(), "f_builtins")\n    original = namespace.get("enumerate", enumerate)\n    try:\n        namespace["enumerate"] = lambda values: [(user, None)]\n        for index, unused in enumerate([1]):\n            cursor.execute(f"SELECT {index}")\n    finally:\n        namespace["enumerate"] = original\n', ((CRITICAL, 10),)),
    ('list-conditional-item', '    queries = ["SELECT 1"]\n    first = queries[0] if queries else "SELECT 1"\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(first)\n    cursor.execute(queries[1])\n', ((CRITICAL, 6),)),
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
    ('gen-next-default-sql', '    pending = ("SELECT 1" for item in [])\n    cursor.execute(next(pending, f"SELECT {user}"))\n', ((CRITICAL, 3),)),
    ('gen-unpack-sql', '    query, = (f"SELECT {item}" for item in [user])\n    cursor.execute(query)\n', ((CRITICAL, 3),)),
    ('gen-loop-sql', '    for query in (f"SELECT {item}" for item in [user]):\n        cursor.execute(query)\n', ((CRITICAL, 3),)),
    ('gen-extend-sql', '    queries = []\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('gen-min-key-sql', '    pending = (f"SELECT {user}" for item in [1])\n    cursor.execute(min(pending, key=len))\n', ((CRITICAL, 3),)),
    ('gen-reallocate-sql', '    for item in rows:\n        pending = (f"SELECT {user}" for unused in [1])\n        for query in pending:\n            cursor.execute(query)\n', ((CRITICAL, 5),)),
    ('gen-receiver-rebind-sql', '    queries = []\n    queries.extend(None for item in [1] if (queries := [f"SELECT {user}"]))\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
    ('gen-mixed-unsafe-list', '    pending = [f"SELECT {user}"] if rows else ("SELECT 1" for item in [1])\n    for query in pending:\n        cursor.execute(query)\n', ((CRITICAL, 4),)),
)


def program(body):
    return 'def run(cursor, qs, user, rows):\n' + body


def incomplete_program():
    unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
    return program(f'    first = cursor.execute({unsafe}).fetchone()[0]\n'
                   '    queries = []\n    alias = queries\n'
                   f'    queries.extend({unsafe} for item in [1])\n'
                   '    return first\n')


def incomplete_closure_program():
    return program('    queries = []\n    def consume(value):\n'
                   '        queries.append(cursor.execute(value).fetchone()[0])\n'
                   '        pending = (value for item in [1])\n        pending.send(None)\n'
                   '    consume(f"SELECT count(*) FROM users WHERE name = \'{user}\'")\n'
                   '    return queries[0]\n')


def sqlite_witness(artifacts, name, source, *, mode='capture', value="' OR 1=1 --", flag=False, optimize=False):
    """Execute test-authored source in a bounded child, with data in argv.

    This is a real SQLite witness, not scanner output. A separate interpreter
    keeps fixture definitions and decorators out of the test runner's globals.
    Isolated Python mode is not a security sandbox for untrusted programs.
    """
    script = artifacts / f'witness-{mode}-{name}.py'
    prelude = '''import json
import sqlite3
import sys
from contextlib import closing

class KeywordCursor:
    def __init__(self, cursor):
        self.cursor = cursor

    def execute(self, query, params=()):
        return self.cursor.execute(query, params)

class Arbitrary:
    def Identifier(self, value):
        return value

    def check(self, value):
        return value

def validate_sql_identifier(value):
    if value not in {'alice', 'bob'}:
        raise ValueError('identifier not allowed')

'''
    invocation = '''
inputs = json.loads(sys.argv[1])
with closing(sqlite3.connect(':memory:')) as connection:
    connection.execute('CREATE TABLE users(name TEXT)')
    connection.executemany('INSERT INTO users VALUES (?)', [('alice',), ('bob',)])
    cursor = connection.cursor()
    if inputs['mode'] == 'validation':
        actual = run(cursor, inputs['value'], "' OR 1=1 --", inputs['flag'])
    elif inputs['mode'] == 'bindings':
        actual = run(cursor, inputs['value'], Arbitrary())
    elif inputs['mode'] in {'capture', 'keyword'}:
        if inputs['mode'] == 'keyword':
            cursor = KeywordCursor(cursor)
        actual = run(cursor, None, inputs['value'], [])
    else:
        raise ValueError('unknown witness mode')
print(json.dumps({'rows': actual, 'python': sys.version, 'sqlite_version': sqlite3.sqlite_version,
                  'optimize': sys.flags.optimize}))
'''
    script.write_text(prelude + source + invocation, encoding='utf-8')
    command = [sys.executable, '-I', '-B', *(['-O'] if optimize else []), str(script),
               json.dumps({'mode': mode, 'value': value, 'flag': flag})]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    except subprocess.TimeoutExpired as exc:
        for suffix, output in (('.stdout.log', exc.stdout), ('.stderr.log', exc.stderr)):
            text = output if isinstance(output, str) else (output or b'').decode('utf-8', errors='replace')
            script.with_suffix(suffix).write_text(text, encoding='utf-8')
        script.with_suffix('.timeout.txt').write_text(str(exc), encoding='utf-8')
        raise AssertionError(f'SQLite witness timed out: {script}') from exc
    script.with_suffix('.stdout.log').write_text(result.stdout, encoding='utf-8')
    script.with_suffix('.stderr.log').write_text(result.stderr, encoding='utf-8')
    if result.returncode != 0:
        raise AssertionError(f'SQLite witness exited {result.returncode}: {script}\n{result.stderr}')
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f'SQLite witness emitted invalid JSON: {script}') from exc
    if (not isinstance(payload, dict) or type(payload.get('rows')) is not int
            or not isinstance(payload.get('python'), str) or not isinstance(payload.get('sqlite_version'), str)):
        raise AssertionError(f'SQLite witness emitted invalid result fields: {script}')
    return payload


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

    def test_sqlite_witness_fails_on_child_errors_and_invalid_results(self):
        for name, source in (
                ('child-error', 'def run(*args):\n    raise RuntimeError("fixture failed")\n'),
                ('invalid-result', 'def run(*args):\n    return "not a row count"\n')):
            with self.subTest(case=name), self.assertRaises(AssertionError):
                sqlite_witness(self.artifacts, name, source)

    def test_value_capture_programs(self):
        for name, body, expected in CASES:
            with self.subTest(case=name):
                self.inspect(name, program(body), expected)

    def test_lazy_generator_programs(self):
        for name, body, expected in GENERATOR_CASES:
            with self.subTest(case=name):
                self.inspect(name, program(body), expected)

    def test_resolved_generator_consumers_keep_returns_and_sinks(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        cases = (
            ('collect-list', '        return [query for query in values]\n', '', 2),
            ('collect-mapping', '        result = {query: query for query in values}\n'
             '        return list(result.values())\n', '', 2),
            ('callee-builtin-frame', '        result = {query: query for query in values}\n'
             '        return list(result.values())\n', '        list = 0\n', 2),
            ('callee-finally-return', '        try:\n            return [query for query in values]\n'
             '        finally:\n            return ["SELECT count(*) FROM users WHERE name = \'alice\'"]\n', '', 1),
        )
        for name, collect, setup, rows in cases:
            source = ('class Engine:\n    def collect(self, values):\n' + collect
                      + '    def run(self, cursor, user):\n' + setup
                      + f'        result = self.collect({unsafe} for unused in [1])\n'
                      + '        return cursor.execute(result[0]).fetchone()[0]\n'
                      + program('    return Engine().run(cursor, user)\n'))
            line = next(index for index, text in enumerate(source.splitlines(), 1)
                        if 'return cursor.execute' in text)
            with self.subTest(case=name):
                self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], rows)
                self.inspect(name, source, ((CRITICAL, line),) if rows == 2 else ())
        source = ('class Engine:\n    def consume(self, values, cursor):\n'
                  '        for query in values:\n            cursor.execute(query)\n'
                  '    def run(self, cursor, user):\n'
                  f'        self.consume(({unsafe} for unused in [1]), cursor=cursor)\n'
                  '        return cursor.execute("SELECT count(*) FROM users").fetchone()[0]\n'
                  + program('    return Engine().run(cursor, user)\n'))
        self.assertEqual(sqlite_witness(self.artifacts, 'callee-sql-sink', source)['rows'], 2)
        self.inspect('callee-sql-sink', source, ((CRITICAL, 4),))

    def test_resolved_consumers_cannot_export_cursor_or_mutate_caller_heap(self):
        unsafe = 'f"SELECT {user}"'
        for name, body, signature, actual in (
                ('retained-cursor', '        return values\n', '', ''),
                ('aliased-cursor', '        saved = values\n        return list(saved)\n', '', ''),
                ('caller-heap', '        for query in values:\n            target.items.append(query)\n', ', target', ', target=target'),
                ('captured-global', '        return [query for query in values if enabled]\n', '', '')):
            prefix = 'enabled = True\n' if name == 'captured-global' else ''
            source = (prefix + 'class Engine:\n' + f'    def consume(self, values{signature}):\n' + body
                      + '    def run(self, cursor, user, target):\n'
                      + f'        self.consume(({unsafe} for unused in [1]){actual})\n'
                      + '        cursor.execute("SELECT %s", (user,))\n')
            with self.subTest(case=name):
                path = self.artifacts / f'consumer-refusal-{name}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator.*incomplete'):
                    list(detector.find([path]))

    def test_consumer_projection_cannot_hide_opaque_sql_side_effects(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        source = ('class Token:\n    def __init__(self, query, cursor):\n'
                  '        self.query = query\n        self.cursor = cursor\n'
                  '    def signature(self):\n'
                  '        return self.cursor.execute(self.query).fetchone()[0]\n'
                  'class Engine:\n    def collect(self, values):\n'
                  '        return [value.signature() for value in values]\n'
                  '    def run(self, cursor, user):\n'
                  f'        return self.collect(Token({unsafe}, cursor) for unused in [1])[0]\n'
                  + program('    return Engine().run(cursor, user)\n'))
        self.assertEqual(sqlite_witness(self.artifacts, 'consumer-opaque-effect', source)['rows'], 2)
        path = self.artifacts / 'consumer-opaque-effect.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'consumer call effects.*incomplete'):
            list(detector.find([path]))

    def test_consumer_callable_identity_and_exhaustion(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        for name, source in (
                ('decorated', 'def decorate(fn):\n    return fn\n@decorate\ndef collect(values):\n'
                 '    return [query for query in values]\n'
                 + program(f'    collect({unsafe} for unused in [1])\n'
                           '    cursor.execute("SELECT %s", (user,))\n')),
                ('escaped-method', 'class Engine:\n    def collect(self, values):\n'
                 '        return [query for query in values]\n'
                 '    def run(self, cursor, user):\n        held = self.collect\n'
                 f'        self.collect({unsafe} for unused in [1])\n'
                 '        cursor.execute("SELECT %s", (user,))\n'),
                ('undefined-global', 'def collect(values):\n'
                 '    return [query for query in values if undefined_flag]\n'
                 + program(f'    collect({unsafe} for unused in [1])\n'
                           '    cursor.execute("SELECT %s", (user,))\n'))):
            with self.subTest(case=name):
                path = self.artifacts / f'consumer-identity-{name}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator.*incomplete'):
                    list(detector.find([path]))
        source = ('class Engine:\n    def collect(self, values):\n'
                  '        return [query for query in values]\n'
                  '    def run(self, cursor, user):\n'
                  f'        pending = ({unsafe} for unused in [1])\n'
                  '        discarded = list(pending)\n        return len(self.collect(pending))\n'
                  + program('    return Engine().run(cursor, user)\n'))
        self.assertEqual(sqlite_witness(self.artifacts, 'consumer-exhaustion', source)['rows'], 0)
        self.inspect('consumer-exhaustion', source, ())

    def test_consumer_retains_known_sink_before_unsupported_call(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        source = ('def unknown(value):\n    return value\n'
                  'class Engine:\n    def consume(self, values, cursor):\n'
                  '        for query in values:\n            cursor.execute(query)\n'
                  '            unknown(query)\n'
                  '    def run(self, cursor, user):\n'
                  f'        self.consume(({unsafe} for unused in [1]), cursor=cursor)\n')
        path = self.artifacts / 'consumer-partial-sink.py'
        path.write_text(source, encoding='utf-8')
        found = detector.find([path])
        self.assertEqual(next(found)[:4], (CRITICAL, path, 6, 1))
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'consumer call effects.*incomplete'):
            list(found)

    def test_sql_suppressions_require_owned_comments_and_exact_rules(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        cases = (
            ('marker-in-query', '    return cursor.execute(' + unsafe[:-1] + ' -- ubs:ignore").fetchone()[0]\n', True),
            ('preceding-literal', '    note = "ubs:ignore"\n    return cursor.execute(' + unsafe + ').fetchone()[0]\n', True),
            ('wrong-rule', '    # ubs:ignore[py.io.open-missing-with]\n    return cursor.execute(' + unsafe + ').fetchone()[0]\n', True),
            ('wrong-tier', '    # ubs:ignore[py.security.sql-injection-unproven]\n    return cursor.execute(' + unsafe + ').fetchone()[0]\n', True),
            ('previous-statement', '    note = 0  # ubs:ignore\n    return cursor.execute(' + unsafe + ').fetchone()[0]\n', True),
            ('exact-rule', '    # ubs:ignore[py.security.sql-injection]\n    return cursor.execute(' + unsafe + ').fetchone()[0]\n', False),
            ('bare-rule', '    # ubs:ignore\n    return cursor.execute(' + unsafe + ').fetchone()[0]\n', False),
            ('inline-rule', '    return cursor.execute(' + unsafe + ').fetchone()[0]  # ubs:ignore[py.security.sql-injection]\n', False),
            ('multiline-rule', '    return cursor.execute(\n        ' + unsafe + ',\n'
             '        # ubs:ignore[py.security.sql-injection]\n    ).fetchone()[0]\n', False),
        )
        for name, body, emitted in cases:
            source = program(body)
            line = next(index for index, text in enumerate(source.splitlines(), 1) if 'return cursor.execute' in text)
            with self.subTest(case=name):
                self.assertEqual(sqlite_witness(self.artifacts, 'suppression-' + name, source)['rows'], 2)
                self.inspect('suppression-' + name, source, ((CRITICAL, line),) if emitted else ())
        for marker, expected in (('py.security.sql-injection', ((WARNING, 3),)),
                                 ('py.security.sql-injection-unproven', ())):
            self.inspect('suppression-warning-' + marker,
                         program(f'    # ubs:ignore[{marker}]\n    cursor.execute(f"SELECT {{UNKNOWN}}")\n'), expected)
        source = incomplete_program().replace('.fetchone()[0]\n',
                    '.fetchone()[0]  # ubs:ignore[py.security.sql-injection]\n', 1)
        path = self.artifacts / 'suppression-still-incomplete.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator consumer.*incomplete'):
            list(detector.find([path]))

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
            '    pending = (f"SELECT {item}" for item in [user])\n    consume(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = ((query := f"SELECT {item}") for item in [user])\n    next(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = (f"SELECT {item}" for item in [user])\n    list = unknown\n    list(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = (f"SELECT {item}" for item in [user])\n    if rows:\n        pending = None\n    list(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = (f"SELECT {item}" for item in [user])\n    def nested():\n        list(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
        )
        for index, body in enumerate(bodies):
            with self.subTest(case=index):
                path = self.artifacts / f'generator-boundary-{index}.py'
                path.write_text(program(body), encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator.*incomplete'):
                    list(detector.find([path]))

    def test_no_sink_refusal_shapes_need_no_sql_flow(self):
        # Since 607712f9 a file with no modeled SQL sink call skips SQL flow. These are refusal shapes from this
        # file with no sink: they are complete and clean. The refusal fixtures keep a trailing sink for that reason.
        for name, body in (
                ('generator-boundary', '    pending = (f"SELECT {item}" for item in [user])\n    consume(pending)\n'),
                ('list-consumer', '    queries = []\n    alias = queries\n'
                 '    queries.extend(f"SELECT {user}" for item in [1])\n'),
                ('closure-predicate', '    queries = ["SELECT 1"]\n    def add(value):\n        queries.append(value)\n'
                 '    any(hold(queries) for query in queries)\n    add(f"SELECT {user}")\n')):
            with self.subTest(control=name):
                path = self.artifacts / f'no-sink-control-{name}.py'
                path.write_text(program(body), encoding='utf-8')
                self.assertEqual(list(detector.find([path])), [])

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
            # Repeated read-only projection is supported; discarded SQL text
            # is not a sink, and later yields must retain their current risk.
            ('repeated-unused', '    pending = (f"SELECT {user}" for item in rows)\n    next(pending)\n    next(pending)\n', ()),
            ('repeated-unsafe', '    pending = (f"SELECT {user}" for item in [1, 2])\n    next(pending)\n    cursor.execute(next(pending))\n', ((CRITICAL, 4),)),
            ('repeated-safe', '    pending = ("SELECT 1" for item in [1, 2])\n    next(pending)\n    cursor.execute(next(pending))\n', ()),
            ('repeated-late-unsafe', '    query = "SELECT 1"\n    pending = (query for item in [1, 2])\n    next(pending)\n    query = f"SELECT {user}"\n    cursor.execute(next(pending))\n', ((CRITICAL, 6),)),
            ('repeated-late-safe', '    query = f"SELECT {user}"\n    pending = (query for item in [1, 2])\n    next(pending)\n    query = "SELECT 1"\n    cursor.execute(next(pending))\n', ()),
        )
        for name, body, expected in cases:
            with self.subTest(case=name):
                self.inspect('next-' + name, program(body), expected)

    def test_next_projection_refuses_unmodeled_effects(self):
        bodies = (
            '    pending = ((query := f"SELECT {user}") for item in rows)\n    next(pending, None)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = (cursor.execute(f"SELECT {user}") for item in rows)\n    next(pending, None)\n',
            '    pending = (f"SELECT {user}" for item in rows)\n    next(pending)\n    list(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = (f"SELECT {user}" for item in rows)\n    next = unknown\n    next(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = (f"SELECT {user}" for item in rows)\n    alias = pending\n    next(pending)\n    tuple(alias)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    other = (f"SELECT {user}" for item in rows)\n    pending = (list(other) for item in [1])\n    next(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
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
                exec(compile(source, '<test-authored-next>', 'exec'), namespace)  # ubs:ignore[py.security.eval-exec-usage,py.eval-exec] Only literal test-authored source; no external input.
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

    def test_known_sql_findings_survive_incomplete_flow(self):
        self._assert_known_sql_before_incomplete('known-before-incomplete', incomplete_program(), 2)
        self._assert_known_sql_before_incomplete('closure-before-incomplete', incomplete_closure_program(), 4)

    def _assert_known_sql_before_incomplete(self, name, source, sink_line):
        from ubs_core.py_scan import _detector_job

        self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], 2)
        path = self.artifacts / (name + '.py')
        path.write_text(source, encoding='utf-8')
        found = detector.find([path])
        first = next(found)
        self.assertEqual((first[0], first[1], first[2], first[3]), (CRITICAL, path, sink_line, 1))
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator consumer.*incomplete'):
            list(found)
        records, problems = _detector_job('sql_injection', [path], set())
        try:
            available = [json.loads(record) for record in records.splitlines()]
        except json.JSONDecodeError as exc:
            self.fail(f'Detector returned invalid NDJSON for {path}: {exc}')
        self.assertEqual([(item['rule'], item['line']) for item in available], [(CRITICAL, sink_line)])
        self.assertEqual(len(problems), 1)
        self.assertIn('SQLFlowLimit', problems[0])
        self.assertIn('analysis is incomplete', problems[0])

    @unittest.skipUnless((ROOT / 'ubs').is_file(), 'real CLI requires full checkout')
    def test_real_cli_retains_known_findings_in_partial_reports(self):
        self._assert_partial_cli('partial', incomplete_program(), 2)
        self._assert_partial_cli('closure-partial', incomplete_closure_program(), 4)

    def _assert_partial_cli(self, name, source, sink_line):
        for entry in ('ubs', 'modules/ubs-python.sh'):
            for fmt in ('json', 'sarif'):
                with self.subTest(entry=entry, format=fmt):
                    folder = self.artifacts / (name + '-' + entry.replace('/', '-') + '-' + fmt)
                    folder.mkdir()
                    path = folder / 'case.py'
                    path.write_text(source, encoding='utf-8')
                    for child in ('home', 'cache', 'tmp'):
                        (folder / child).mkdir()
                    env = {key: value for key, value in os.environ.items() if not key.startswith('UBS_')}
                    env.update(HOME=str(folder / 'home'), XDG_CACHE_HOME=str(folder / 'cache'),
                               TMPDIR=str(folder / 'tmp'), UBS_KEEP_TEMP='1', UBS_NO_CACHE='1',
                               UBS_NO_AUTO_UPDATE='1', ENABLE_UV_TOOLS='0',
                               PYTHONDONTWRITEBYTECODE='1', NO_COLOR='1')
                    command = ['bash', str(ROOT / entry), '--ci', '--no-color', '--format=' + fmt,
                               '--only=python' if entry == 'ubs' else '--no-uv', str(path)]
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
                        'command': command, 'status': result.returncode,
                        'detector_sha256': self.identity,
                        'entry_sha256': hashlib.sha256((ROOT / entry).read_bytes()).hexdigest(),
                        'elapsed_seconds': time.perf_counter() - started,
                    }, indent=2) + '\n', encoding='utf-8')
                    self.assertEqual(result.returncode, 2, result.stderr)
                    try:
                        report = json.loads(result.stdout)
                    except json.JSONDecodeError as exc:
                        self.fail(f'CLI emitted invalid JSON: {command}; evidence: {folder}: {exc}')
                    self.assertIn('SQLFlowLimit', result.stdout)
                    if fmt == 'json':
                        self.assertEqual(report['status'], 'partial')
                        scans = report['scanners'] if entry == 'ubs' else [report]
                        self.assertEqual(len(scans), 1)
                        self.assertEqual(scans[0]['status'], 'partial')
                        lines = [sample['line'] for finding in scans[0]['findings']
                                 if finding.get('rule_id', finding.get('rule')) == CRITICAL
                                 for sample in finding['samples']]
                    else:
                        self.assertTrue(any(invocation.get('executionSuccessful') is False
                                            for run in report['runs'] for invocation in run.get('invocations', [])))
                        lines = [finding['locations'][0]['physicalLocation']['region']['startLine']
                                 for run in report['runs'] for finding in run.get('results', [])
                                 if finding['ruleId'] == CRITICAL]
                    self.assertEqual(lines, [sink_line], folder)

    def test_opaque_consumers_use_projected_values_without_advancing_aliases(self):
        cases = (
            ('discard-query', '    consume(None for item in [f"SELECT {user}"])\n', ()),
            ('discard-filtered-query', '    consume("id = 1" for item in [f"SELECT {user}"] if rows)\n', ()),
            ('integer-range', '    next(index for index in range(user + 2))\n', ()),
            ('repeated-opaque',
             '    pending = (None for item in [user])\n    consume(pending)\n    consume(pending)\n', ()),
            ('integer-range-eager-sink',
             '    next(index for index in range(cursor.execute(f"SELECT {user}")))\n', ((CRITICAL, 2),)),
            ('opaque-does-not-clean-outer',
             '    query = f"SELECT {user}"\n    consume(None for item in [query])\n    cursor.execute(query)\n',
             ((CRITICAL, 4),)),
        )
        for name, body, expected in cases:
            with self.subTest(case=name):
                self.inspect('opaque-' + name, program(body), expected)

        refusals = (
            '    range = unknown\n    consume(index for index in range(f"SELECT {user}"))\n    cursor.execute("SELECT %s", (user,))\n',
            '    pending = (None for item in [user])\n    consume(pending)\n    list(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    query = f"SELECT {user}"\n    consume((query := "SELECT 1") for item in [1])\n    cursor.execute(query)\n',
            '    consume(cursor.execute(f"SELECT {user}") for item in [1])\n',
            '    consume(f"name = {item}" for item in [user])\n    cursor.execute("SELECT %s", (user,))\n',
            '    query = "SELECT 1"\n    pending = (query for item in [1])\n    consume(pending)\n    query = f"SELECT {user}"\n    consume(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
        )
        for index, body in enumerate(refusals):
            with self.subTest(refusal=index):
                path = self.artifacts / f'opaque-refusal-{index}.py'
                path.write_text(program(body), encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator.*incomplete'):
                    list(detector.find([path]))

    def test_collection_concatenation_preserves_contents_without_fabricating_sql(self):
        cases = (
            ('list-concat', '    left = [1]\n    right = [2]\n    consume(item for item in left + right)\n', ()),
            ('tuple-concat', '    left = (1,)\n    right = (2,)\n    consume(item for item in left + right)\n', ()),
            ('list-comp-concat', '    left = [item for item in range(user)]\n    right = [3]\n    consume(item for item in left + right)\n', ()),
            ('list-sql-contents', '    left = [f"name = {user}"]\n    right = []\n    qs.extra(where=left + right)\n', ((CRITICAL, 4),)),
            ('tuple-sql-contents', '    left = (f"name = {user}",)\n    right = ()\n    qs.extra(where=left + right)\n', ((CRITICAL, 4),)),
            ('list-element-remains-string', '    left = [f"name = {user}"]\n    for item in left:\n        qs.extra(where=[item + " "])\n', ((CRITICAL, 4),)),
        )
        for name, body, expected in cases:
            with self.subTest(case=name):
                self.inspect(name, program(body), expected)
        for index, body in enumerate((
                '    left = []\n    if rows:\n        left = user\n    consume(item for item in left + [])\n    cursor.execute(left[0])\n',
                '    left = [f"name = {user}"]\n    consume(item for item in left + [])\n    cursor.execute(left[0])\n',
                '    left = [1]\n    left = user\n    consume(item for item in left + [])\n    cursor.execute(left[0])\n')):
            with self.subTest(refusal=index):
                path = self.artifacts / f'collection-refusal-{index}.py'
                path.write_text(program(body), encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator.*incomplete'):
                    list(detector.find([path]))

    def test_indexes_select_values_without_becoming_sql_text(self):
        cases = (
            ('lookup-key-is-data', '    values = ["SELECT 1"]\n    cursor.execute(values[len(f"SELECT {user}") % 1])\n', ()),
            ('slice-index-is-data', '    query = "SELECT 1"\n    cursor.execute(query[:len(f"SELECT {user}")])\n', ()),
            ('selected-value-is-sql', '    values = [f"SELECT {user}"]\n    cursor.execute(values[0])\n', ((CRITICAL, 3),)),
            ('index-side-effect-is-eager', '    query = "SELECT 1"\n    values = ["SELECT 1"]\n    unused = values[(query := f"SELECT {user}") and 0]\n    cursor.execute(query)\n', ((CRITICAL, 5),)),
            ('index-sink-is-eager', '    values = ["SELECT 1"]\n    unused = values[(cursor.execute(f"SELECT {user}"), 0)[1]]\n', ((CRITICAL, 3),)),
        )
        for name, body, expected in cases:
            with self.subTest(case=name):
                self.inspect(name, program(body), expected)

    def test_read_only_generator_loops_recheck_late_bindings(self):
        cases = (
            ('loop-range', '    for item in (index for index in range(user)):\n        pass\n', ()),
            ('loop-keeps-query', '    query = f"SELECT {user}"\n    for item in (None for row in rows):\n        cursor.execute(query)\n', ((CRITICAL, 4),)),
            ('loop-discarded-sql', '    for item in ("SELECT 1" for query in [f"SELECT {user}"]):\n        cursor.execute(item)\n', ()),
            ('loop-sql-value', '    for item in (f"SELECT {value}" for value in [user]):\n        cursor.execute(item)\n', ((CRITICAL, 3),)),
            ('loop-late-sql-value', '    query = "SELECT 1"\n    pending = (query for row in rows)\n    for item in pending:\n        cursor.execute(item)\n        query = f"SELECT {user}"\n', ((CRITICAL, 5),)),
            ('loop-mixed-iterable', '    pending = [f"SELECT {user}"] if rows else (f"SELECT {user}" for item in [1])\n    for item in pending:\n        cursor.execute(item)\n', ((CRITICAL, 4),)),
            ('loop-mixed-unsafe-list', '    pending = [f"SELECT {user}"] if rows else ("SELECT 1" for item in [1])\n    for item in pending:\n        cursor.execute(item)\n', ((CRITICAL, 4),)),
        )
        for name, body, expected in cases:
            with self.subTest(case=name):
                self.inspect(name, program(body), expected)
        refusals = (
            '    query = "SELECT 1"\n    pending = ((query := f"SELECT {user}") for row in rows)\n    for item in pending:\n        pass\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = ((query := "SELECT 1") for row in rows)\n    for item in pending:\n        pass\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = (None for row in rows)\n    for item in pending:\n        break\n    list(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    for item in (cursor.execute(f"SELECT {user}") for row in rows):\n        pass\n',
        )
        for index, body in enumerate(refusals):
            with self.subTest(refusal=index):
                path = self.artifacts / f'streaming-refusal-{index}.py'
                path.write_text(program(body), encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator.*incomplete'):
                    list(detector.find([path]))

    def test_read_only_next_and_unpacking_capture_sql_values(self):
        cases = (
            ('next-sql', '    pending = (f"SELECT {item}" for item in [user])\n    cursor.execute(next(pending))\n', ((CRITICAL, 3),)),
            ('next-clean', '    cursor.execute(next("SELECT 1" for item in [user]))\n', ()),
            ('next-default', '    pending = ("SELECT 1" for item in [])\n    cursor.execute(next(pending, f"SELECT {user}"))\n', ((CRITICAL, 3),)),
            ('next-default-eager', '    query = "SELECT 1"\n    pending = (query for item in [1])\n    value = next(pending, (query := f"SELECT {user}"))\n    cursor.execute(value)\n', ((CRITICAL, 5),)),
            ('next-rechecks-free-variable', '    query = "SELECT 1"\n    pending = (query for item in [1, 2])\n    next(pending)\n    query = f"SELECT {user}"\n    cursor.execute(next(pending))\n', ((CRITICAL, 6),)),
            ('next-done-default', '    pending = (f"SELECT {user}" for item in [1])\n    list(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n', ()),
            ('min-key-sql', '    pending = (f"SELECT {user}" for item in [1])\n    cursor.execute(min(pending, key=len))\n', ((CRITICAL, 3),)),
            ('max-default-sql', '    pending = ("SELECT 1" for item in [])\n    cursor.execute(max(pending, key=len, default=f"SELECT {user}"))\n', ((CRITICAL, 3),)),
            ('sorted-key-sql', '    pending = (f"SELECT {user}" for item in [1])\n    cursor.execute(sorted(pending, key=len, reverse=True)[0])\n', ((CRITICAL, 3),)),
            ('unpack-sql', '    query, = (f"SELECT {item}" for item in [user])\n    cursor.execute(query)\n', ((CRITICAL, 3),)),
            ('unpack-clean', '    query, = ("SELECT 1" for item in [user])\n    cursor.execute(query)\n', ()),
            ('unpack-drains-alias', '    pending = (f"SELECT {item}" for item in [user])\n    alias = pending\n    query, = pending\n    qs.extra(where=list(alias))\n    cursor.execute(query)\n', ((CRITICAL, 6),)),
            ('unpack-repeated-allocation', '    for item in rows:\n        query, = (f"SELECT {user}" for unused in [1])\n        cursor.execute(query)\n', ((CRITICAL, 4),)),
        )
        for name, body, expected in cases:
            with self.subTest(case=name):
                self.inspect(name, program(body), expected)
        refusals = (
            '    query, = ((query := "SELECT 1") for item in [1, 2])\n    cursor.execute(query)\n',
            '    query, = (cursor.execute(f"SELECT {user}") for item in [1])\n',
            '    next = consume\n    next(f"SELECT {user}" for item in [1])\n    cursor.execute("SELECT %s", (user,))\n',
            '    pending = (f"SELECT {user}" for item in [1, 2])\n    next(pending)\n    list(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = [f"SELECT {user}"] if rows else ("SELECT 1" for item in [1])\n    list(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = ((query := "SELECT 1") for item in [1])\n    min(pending, key=unknown_callback)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    pending = ((query := "SELECT 1") for item in [1])\n    min(pending, key=lambda item: callback(item))\n    cursor.execute(next(pending, "SELECT 1"))\n',
        )
        for index, body in enumerate(refusals):
            with self.subTest(refusal=index):
                path = self.artifacts / f'partial-read-refusal-{index}.py'
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
            ('next-value', f'    pending = ({unsafe} for item in [1])\n    return cursor.execute(next(pending)).fetchone()[0]\n', 2, ((CRITICAL, 3),)),
            ('next-repeated-unsafe', f'    pending = ({unsafe} for item in [1, 2])\n    next(pending)\n    return cursor.execute(next(pending)).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('next-repeated-safe', f'    pending = ({fixed} for item in [1, 2])\n    next(pending)\n    return cursor.execute(next(pending)).fetchone()[0]\n', 1, ()),
            ('next-repeated-late-unsafe', f'    query = {fixed}\n    pending = (query for item in [1, 2])\n    next(pending)\n    query = {unsafe}\n    return cursor.execute(next(pending)).fetchone()[0]\n', 2, ((CRITICAL, 6),)),
            ('next-repeated-late-safe', f'    query = {unsafe}\n    pending = (query for item in [1, 2])\n    next(pending)\n    query = {fixed}\n    return cursor.execute(next(pending)).fetchone()[0]\n', 1, ()),
            ('next-empty-default', f'    pending = ({fixed} for item in [])\n    return cursor.execute(next(pending, {unsafe})).fetchone()[0]\n', 2, ((CRITICAL, 3),)),
            ('next-parameterized', '    pending = ("SELECT count(*) FROM users WHERE name = ?" for item in [1])\n    return cursor.execute(next(pending), (user,)).fetchone()[0]\n', 0, ()),
            ('unpack-value', f'    query, = ({unsafe} for item in [1])\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 3),)),
            ('unpack-parameterized', '    query, = ("SELECT count(*) FROM users WHERE name = ?" for item in [1])\n    return cursor.execute(query, (user,)).fetchone()[0]\n', 0, ()),
            ('unpack-arity-error', f'    pending = ({unsafe} for item in [1, 2, 3])\n    try:\n        query, = pending\n    except ValueError:\n        return cursor.execute(next(pending)).fetchone()[0]\n', 2, ((CRITICAL, 6),)),
            ('stream-value', f'    for query in ({unsafe} for item in [1]):\n        return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 3),)),
            ('stream-parameterized', '    for query in ("SELECT count(*) FROM users WHERE name = ?" for item in [1]):\n        return cursor.execute(query, (user,)).fetchone()[0]\n', 0, ()),
            ('extend-value', f'    queries = []\n    queries.extend({unsafe} for item in [1])\n    return cursor.execute(queries[0]).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('extend-parameterized', '    queries = []\n    queries.extend("SELECT count(*) FROM users WHERE name = ?" for item in [1])\n    return cursor.execute(queries[0], (user,)).fetchone()[0]\n', 0, ()),
            ('extend-prefix-error', f'    queries = []\n    try:\n        queries.extend({unsafe} for item in [1, 0] if 1 / item)\n    except ZeroDivisionError:\n        return cursor.execute(queries[0]).fetchone()[0]\n', 2, ((CRITICAL, 6),)),
            ('extend-deferred-store', f'    query = {fixed}\n    queries = []\n    queries.extend((query := {unsafe}) for item in [1])\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 5),)),
            ('extend-cleans-store', f'    query = {unsafe}\n    queries = []\n    queries.extend((query := {fixed}) for item in [1])\n    return cursor.execute(query).fetchone()[0]\n', 1, ()),
            ('extend-rebinds-receiver', f'    queries = []\n    queries.extend(None for item in [1] if (queries := [{unsafe}]))\n    return cursor.execute(queries[0]).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('extend-rebinds-receiver-clean', f'    queries = [{unsafe}]\n    queries.extend(None for item in [1] if (queries := [{fixed}]))\n    return cursor.execute(queries[0]).fetchone()[0]\n', 1, ()),
            ('min-key', f'    pending = ({unsafe} for item in [1])\n    return cursor.execute(min(pending, key=len)).fetchone()[0]\n', 2, ((CRITICAL, 3),)),
            ('max-empty-default', f'    pending = ({fixed} for item in [])\n    return cursor.execute(max(pending, key=len, default={unsafe})).fetchone()[0]\n', 2, ((CRITICAL, 3),)),
            ('stream-reallocation', f'    for query in [{fixed}, {unsafe}]:\n        pending = (item for item in [query])\n        for selected in pending:\n            pass\n    return cursor.execute(selected).fetchone()[0]\n', 2, ((CRITICAL, 6),)),
            ('stream-reallocation-clean', f'    for query in [{fixed}, {fixed}]:\n        pending = (item for item in [query])\n        for selected in pending:\n            pass\n    return cursor.execute(selected).fetchone()[0]\n', 1, ()),
        )
        for name, body, rows, expected in witnesses:
            with self.subTest(case=name):
                source = program(body)
                witness = sqlite_witness(self.artifacts, name, source)
                actual = witness['rows']
                (self.artifacts / f'sqlite-generator-{name}-execution.json').write_text(json.dumps({
                    'case': name, 'expected_rows': rows, 'actual_rows': actual,
                    'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
                    'python': witness['python'], 'sqlite_version': witness['sqlite_version'],
                }, indent=2) + '\n', encoding='utf-8')
                self.assertEqual(actual, rows)
                self.inspect('sqlite-generator-' + name, source, expected)

    def test_signed_literal_list_indices_preserve_sql(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for spelling, index in (('negative', '-1'), ('positive', '+0'), ('nested', '--0')):
            for operation in ('insert', '__setitem__', 'pop'):
                for kind, query, expected_rows in (('unsafe', unsafe, 2), ('static', safe, 1)):
                    name = f'signed-index-{spelling}-{operation}-{kind}'
                    if operation == 'pop':
                        body = f'    queries = [{query}]\n    selected = queries.pop({index})\n'
                        selected = 'selected'
                    else:
                        body = f'    queries = [{safe}]\n    queries.{operation}({index}, {query})\n'
                        selected = 'queries[0]'
                    source = program(body + f'    return cursor.execute({selected}).fetchone()[0]\n')
                    with self.subTest(case=name):
                        self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], expected_rows)
                        self.inspect(name, source, ((CRITICAL, 4),) if kind == 'unsafe' else ())

    def test_signed_numeric_list_insert_retains_value_flow(self):
        for index in ('-1', '+0', '--0'):
            source = program('    indices = [0]\n'
                             f'    indices.insert({index}, 0)\n'
                             '    queries = [f"SELECT count(*) FROM users WHERE name = \'{user}\'"]\n'
                             '    return cursor.execute(queries[indices[0]]).fetchone()[0]\n')
            with self.subTest(index=index):
                name = 'signed-numeric-' + index
                self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], 2)
                self.inspect(name, source, ((CRITICAL, 5),))

    def test_signed_indices_do_not_grant_escaped_list_ownership(self):
        for index in ('-1', '+0'):
            source = program('    queries = []\n    alias = queries\n'
                             f'    queries.insert({index}, f"SELECT count(*) FROM users WHERE name = \'{{user}}\'")\n'
                             '    return cursor.execute(alias[0]).fetchone()[0]\n')
            name = 'signed-escaped-' + index
            with self.subTest(index=index):
                self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], 2)
                path = self.artifacts / (name + '.py')
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'list mutation.*incomplete'):
                    list(detector.find([path]))
        for index in ('user', '-user', 'int("0")', '-1.0'):
            source = program('    queries = ["SELECT 1"]\n'
                             f'    queries.insert({index}, f"SELECT {{user}}")\n'
                             '    cursor.execute(queries[0])\n')
            path = self.artifacts / ('opaque-index-' + hashlib.sha256(index.encode()).hexdigest()[:12] + '.py')
            path.write_text(source, encoding='utf-8')
            with self.subTest(opaque=index), self.assertRaisesRegex(detector.SQLFlowLimit, 'list mutation.*incomplete'):
                list(detector.find([path]))

    def test_fromkeys_captures_key_and_default_sql_separately(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for role in ('keys', 'default'):
            for kind, query, rows in (('unsafe', unsafe, 2), ('static', safe, 1)):
                constructor = (f'dict.fromkeys({query} for item in [1])' if role == 'keys' else
                               f'dict.fromkeys(("chosen" for item in [1]), {query})')
                selected = 'list(mapping)[0]' if role == 'keys' else 'mapping["chosen"]'
                source = program(f'    mapping = {constructor}\n'
                                 f'    return cursor.execute({selected}).fetchone()[0]\n')
                name = f'fromkeys-{role}-{kind}'
                with self.subTest(case=name):
                    self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], rows)
                    self.inspect(name, source, ((CRITICAL, 3),) if kind == 'unsafe' else ())
        for name, constructor, expected in (
                ('select-keys', 'dict.fromkeys((f"SELECT {user}" for item in [1]), "1")', ()),
                ('select-values', 'dict.fromkeys(("chosen" for item in [1]), f"name = {user}")', ((CRITICAL, 3),))):
            with self.subTest(select=name):
                self.inspect('fromkeys-' + name,
                             program(f'    mapping = {constructor}\n    qs.extra(select=mapping)\n'), expected)

    def test_sql_keywords_in_identifiers_do_not_create_sql_templates(self):
        for name in ('call', 'select', 'update', 'drop', 'token'):
            for expression in (f'1 + {name}.end()', f'f"{{{name}}}"'):
                source = (f'def run(cursor, {name}):\n    value = {expression}\n'
                          '    cursor.execute(value)\n')
                with self.subTest(identifier=name, expression=expression):
                    self.inspect('identifier-' + name + '-' + str(expression.startswith('1')), source, ())
            source = (f'def run(cursor, {name}):\n'
                      f'    cursor.execute(f"SELECT {{{name}}}")\n')
            with self.subTest(sql_template=name):
                self.inspect('identifier-real-sql-' + name, source, ((CRITICAL, 2),))

    def test_fromkeys_consumes_once_after_eager_default(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        cases = (
            ('write', f'    query = {safe}\n'
             f'    dict.fromkeys((query := {unsafe}) for item in [1])\n'
             '    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('default-first', f'    query = {unsafe}\n'
             f'    mapping = dict.fromkeys((query for item in [1]), (query := {safe}))\n'
             '    return cursor.execute(list(mapping)[0]).fetchone()[0]\n', 1, ()),
            ('exhausted-alias', f'    query = {safe}\n'
             f'    pending = ((query := {unsafe}) for item in [1])\n'
             '    alias = pending\n    dict.fromkeys(pending)\n'
             f'    query = {safe}\n    dict.fromkeys(alias)\n'
             '    return cursor.execute(query).fetchone()[0]\n', 1, ()),
        )
        for name, body, rows, expected in cases:
            source = program(body)
            with self.subTest(case=name):
                self.assertEqual(sqlite_witness(self.artifacts, 'fromkeys-' + name, source)['rows'], rows)
                self.inspect('fromkeys-' + name, source, expected)

    def test_fromkeys_refuses_rebound_callable_and_heap_callbacks(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        substitute = ('    class Substitute:\n        @staticmethod\n'
                      '        def fromkeys(values):\n'
                      f'            return {{"chosen": {unsafe}}}\n')
        cases = (
            ('shadowed', substitute + '    dict = Substitute\n'
             '    mapping = dict.fromkeys("chosen" for item in [1])\n'
             '    return cursor.execute(mapping["chosen"]).fetchone()[0]\n'),
            ('builtin-rebound', '    import builtins\n' + substitute +
             '    original = builtins.dict\n    try:\n        builtins.dict = Substitute\n'
             '        mapping = dict.fromkeys("chosen" for item in [1])\n'
             '        return cursor.execute(mapping["chosen"]).fetchone()[0]\n'
             '    finally:\n        builtins.dict = original\n'),
            ('mutable-default', f'    shared = [{unsafe}]\n'
             '    mapping = dict.fromkeys(("chosen" for item in [1]), shared)\n'
             '    return cursor.execute(mapping["chosen"][0]).fetchone()[0]\n'),
            ('hash-callback', f'    query = {safe}\n'
             '    class Key:\n        def __hash__(self):\n            nonlocal query\n'
             f'            query = {unsafe}\n            return 0\n'
             '    dict.fromkeys(Key() for item in [1])\n'
             '    return cursor.execute(query).fetchone()[0]\n'),
        )
        for name, body in cases:
            source = program(body)
            with self.subTest(case=name):
                self.assertEqual(sqlite_witness(self.artifacts, 'fromkeys-' + name, source)['rows'], 2)
                path = self.artifacts / ('fromkeys-' + name + '.py')
                path.write_text(source, encoding='utf-8')
                with self.assertRaises(detector.SQLFlowLimit):
                    list(detector.find([path]))

    def test_unrelated_generator_dictionary_does_not_abort_sql_scope(self):
        helper = ('def merge(rows):\n'
                  '    return dict.fromkeys(key for row in rows for key in row)\n')
        reflection = ('def field(obj, name):\n'
                      '    return getattr(obj, name)\n')
        for label, query, expected in (
                ('static', '"SELECT 1"', ()),
                ('unsafe', 'f"SELECT {user}"', ((CRITICAL, 6),))):
            source = helper + reflection + 'def count(cursor, user):\n    cursor.execute(' + query + ')\n'
            self.inspect('unrelated-fromkeys-' + label, source, expected)

    def test_referenced_dictionary_helpers_keep_callback_refusal(self):
        helper = ('def merge(rows):\n'
                  '    return dict.fromkeys(key for row in rows for key in row)\n')
        for name, use in (
                ('direct', '    merge(rows)\n'),
                ('alias', '    collect = merge\n    collect(rows)\n'),
                ('callback', '    process(merge, rows)\n')):
            source = helper + 'def count(cursor, rows):\n' + use + '    cursor.execute("SELECT 1")\n'
            path = self.artifacts / ('referenced-fromkeys-' + name + '.py')
            path.write_text(source, encoding='utf-8')
            with self.subTest(reference=name), self.assertRaisesRegex(
                    detector.SQLFlowLimit, 'fromkeys key callbacks.*incomplete'):
                list(detector.find([path]))

    def test_unrelated_dictionary_body_keeps_eager_default_sink(self):
        source = ('def merge(rows, default=cursor.execute(f"SELECT {source()}")):\n'
                  '    return dict.fromkeys(key for row in rows for key in row)\n')
        self.inspect('fromkeys-eager-definition', source, ((CRITICAL, 1),))

    def test_finite_attribute_names_do_not_invalidate_dictionary_binding(self):
        for name, lookup in (
                ('literal-table', '    getattr(obj, {"class": "classes", "function": "functions"}[kind])\n'),
                ('stable-name', '    field = {"class": "classes", "function": "functions"}[kind]\n'
                 '    getattr(obj, field)\n'),
                ('tuple', '    getattr(obj, ("classes", "functions")[kind])\n'),
                ('concatenation', '    getattr(obj, "class" + "es")\n'),
                ('unrelated-function', '')):
            prefix = ('def field(obj, name):\n    return getattr(obj, name)\n'
                      if name == 'unrelated-function' else '')
            for label, query in (('safe', '"SELECT 1"'), ('unsafe', 'f"SELECT {user}"')):
                source = (prefix + 'def run(cursor, user, obj, kind):\n' + lookup
                          + '    mapping = dict.fromkeys("chosen" for item in [1])\n'
                          + f'    cursor.execute({query})\n')
                line = len(source.splitlines())
                with self.subTest(lookup=name, value=label):
                    self.inspect('fromkeys-lookup-' + name + '-' + label, source,
                                 ((CRITICAL, line),) if label == 'unsafe' else ())

    def test_unknown_or_namespace_attribute_names_keep_binding_refusal(self):
        for name, lookup in (
                ('unknown', '    getattr(obj, field)\n'),
                ('namespace-concatenation', '    getattr(obj, "f_" + "builtins")\n'),
                ('namespace-table', '    getattr(obj, {0: "classes", 1: "f_builtins"}[field])\n'),
                ('rebound', '    field = "classes"\n    field = source()\n    getattr(obj, field)\n'),
                ('conditional', '    if user:\n        field = "classes"\n    getattr(obj, field)\n'),
                ('alias', '    lookup = getattr\n    lookup(obj, field)\n')):
            source = ('def run(cursor, user, obj, field):\n' + lookup
                      + '    mapping = dict.fromkeys("chosen" for item in [1])\n'
                      + '    cursor.execute("SELECT 1")\n')
            path = self.artifacts / ('fromkeys-dynamic-lookup-' + name + '.py')
            path.write_text(source, encoding='utf-8')
            with self.subTest(lookup=name), self.assertRaisesRegex(
                    detector.SQLFlowLimit, 'fromkeys binding.*incomplete'):
                list(detector.find([path]))

    def test_finite_attribute_table_does_not_hide_selector_callbacks(self):
        for name, setup, selector, table in (
                ('hash', '    class Key:\n        def __hash__(self):\n'
                 '            nonlocal query\n            query = f"SELECT {user}"\n'
                 '            return hash("field")\n'
                 '        def __eq__(self, other):\n            return True\n',
                 'Key()', '{"field": "value"}'),
                ('equality', '    class Key:\n        def __hash__(self):\n            return hash("field")\n'
                 '        def __eq__(self, other):\n            nonlocal query\n'
                 '            query = f"SELECT {user}"\n            return True\n',
                 'Key()', '{"field": "value"}'),
                ('index', '    class Key:\n        def __index__(self):\n            nonlocal query\n'
                 '            query = f"SELECT {user}"\n            return 0\n',
                 'Key()', '("value",)'),
                ('imported', '    from callbacks import Key\n', 'Key()', '{"field": "value"}'),
                ('aliased', '    from callbacks import Key as Selector\n    chosen = Selector()\n',
                 'chosen', '{"field": "value"}')):
            source = ('def run(cursor, user, obj):\n    query = "SELECT 1"\n' + setup
                      + f'    field = {table}[{selector}]\n    getattr(obj, field)\n'
                      + '    mapping = dict.fromkeys("chosen" for item in [1])\n'
                      + '    cursor.execute(query)\n')
            path = self.artifacts / ('attribute-selector-callback-' + name + '.py')
            path.write_text(source, encoding='utf-8')
            with self.subTest(callback=name), self.assertRaisesRegex(
                    detector.SQLFlowLimit, 'fromkeys binding.*incomplete'):
                list(detector.find([path]))

    def test_local_execute_and_scalar_are_not_database_operations(self):
        source = ('def scalar(value):\n    return value\n'
                  'class Engine:\n'
                  '    def execute(self, statement):\n        return scalar(statement)\n'
                  '    def run(self, user):\n        return self.execute(f"SELECT {user}")\n')
        self.inspect('local-execute-only', source, ())
        self.inspect('local-execute-next-to-db', source
                     + 'def count(cursor, user):\n    cursor.execute(f"SELECT {user}")\n', ((CRITICAL, 9),))

    def test_local_sql_wrappers_retain_callsite_findings(self):
        for name, prefix, body in (
                ('direct', '', '        return self.cursor.execute(query)\n'),
                ('captured', '', '        action = self.cursor.execute\n        return action(query)\n'),
                ('imported-alias', 'from db_driver import execute as send\n', '        return send(query)\n'),
                ('indirect', '', '        return self.forward(query)\n'
                 '    def forward(self, query):\n        return self.cursor.execute(query)\n'),
                ('recursive', '', '        if flag:\n            return self.forward(query)\n'
                 '        return self.cursor.execute(query)\n'
                 '    def forward(self, query):\n        return self.execute(query)\n'),
                ('reflected', '', '        return getattr(self.cursor, "execute")(query)\n'),
                ('callback-field', '', '        return self.writer(query)\n'),
                ('callback-alias', '', '        saved = query\n        return self.writer(saved)\n'),
                ('callback-indirect', '', '        return self.forward(query)\n'
                 '    def forward(self, query):\n        return self.writer(query)\n'),
                ('imported-forwarder', 'from db_driver import send\n', '        return send(query)\n'),
                ('constructor-capture', '', '        return self.writer(query)\n'
                 '    def __init__(self, cursor):\n        self.writer = cursor.execute\n'),
                ('heap-forward', '', '        self.pending = query\n        return self.writer(self.pending)\n'),
                ('heap-formatted', '', '        self.pending = f"{query}"\n        return self.writer(self.pending)\n'),
                ('heap-converted', '', '        self.pending = str(query)\n        return self.writer(self.pending)\n'),
                ('heap-unpacked', '', '        self.pending, = (query,)\n        return self.writer(self.pending)\n'),
                ('heap-helper-result', 'def wrap(value):\n    return value\n',
                 '        self.pending = wrap(query)\n        return self.writer(self.pending)\n'),
                ('heap-augmented', '', '        self.pending += query\n        return self.writer(self.pending)\n'),
                ('bound-str-alias', '', '        transform = query.__str__\n        return self.writer(transform())\n'),
                ('bound-strip-alias', '', '        transform = query.strip\n        return self.writer(transform())\n'),
                ('bound-transitive-alias', '', '        transform = query.strip\n        action = transform\n'
                 '        return self.writer(action())\n'),
                ('bound-container-alias', '', '        transforms = [query.strip]\n'
                 '        return self.writer(transforms[0]())\n'),
                ('closure-forward', '', '        callback = lambda: self.writer(query)\n        return callback()\n'),
                ('remove-prefix', '', '        return self.writer(query.removeprefix("SQL:"))\n'),
                ('encode', '', '        return self.writer(query.encode())\n'),
                ('padding', '', '        return self.writer(query.ljust(1))\n'),
                ('unpacked-alias', '', '        saved, = (query,)\n        return self.writer(saved)\n'),
                ('augmented-alias', '', '        saved = ""\n        saved += query\n        return self.writer(saved)\n'),
                ('loop-alias', '', '        for saved in [query]:\n            return self.writer(saved)\n')):
            for label, argument in (('unsafe', 'f"SELECT {user}"'), ('static', '"SELECT 1"')):
                source = (prefix + 'class Wrapper:\n    def execute(self, query):\n' + body
                          + '    def run(self, user):\n        return self.execute(' + argument + ')\n')
                line = len(source.splitlines())
                with self.subTest(wrapper=name, value=label):
                    self.inspect('sql-wrapper-' + name + '-' + label, source,
                                 ((CRITICAL, line),) if label == 'unsafe' else ())

    def test_dynamic_execute_dispatch_cannot_inherit_local_method_proof(self):
        for name, source in (
                ('inheritance', 'class Engine(Base):\n'
                 '    def execute(self, statement):\n        return statement\n'),
                ('descriptor', 'class Engine:\n'
                 '    @property\n    def execute(self):\n        return db.execute\n'),
                ('attribute-hook', 'class Engine:\n'
                 '    def __getattribute__(self, name):\n        return lookup(name)\n'
                 '    def execute(self, statement):\n        return statement\n'),
                ('replacement', 'class Engine:\n'
                 '    def execute(self, statement):\n        return statement\n'
                 '    def replace(self, callback):\n        self.execute = callback\n'),
                ('reflected-replacement', 'class Engine:\n'
                 '    def execute(self, statement):\n        return statement\n'
                 '    def replace(self, callback):\n        setattr(self, "execute", callback)\n'),
                ('code-replacement', 'class Engine:\n'
                 '    def execute(self, statement):\n        return statement\n'
                 '    def replace(self, callback):\n        Engine.execute.__code__ = callback.__code__\n')):
            source += '    def run(self, user):\n        return self.execute(f"SELECT {user}")\n'
            with self.subTest(dispatch=name):
                self.inspect('dynamic-execute-' + name, source, ((CRITICAL, len(source.splitlines())),))

    def test_escaped_class_or_receiver_cannot_prove_local_execute(self):
        for name, effect in (
                ('receiver', '        replace_handler(self)\n'),
                ('class', '        replace_handler(Engine)\n')):
            source = ('class Engine:\n'
                      '    def execute(self, statement):\n        return statement\n'
                      '    def run(self, user):\n' + effect
                      + '        return self.execute(f"SELECT {user}")\n')
            self.inspect('escaped-execute-' + name, source, ((CRITICAL, 6),))

    def test_escaped_setter_capabilities_invalidate_local_execute(self):
        owner = ('class Runner:\n    def execute(self, query):\n        return len(query)\n'
                 '    def run(self, user):\n'
                 '        return self.execute(f"SELECT count(*) FROM users WHERE name = \'{user}\'")\n')
        for name, effect in (
                ('setattr-alias', 'install = setattr\nconfigure(install)\n'),
                ('delattr-alias', 'remove = delattr\nconfigure(remove)\n'),
                ('imported-setter', 'from builtins import setattr as install\nconfigure(install)\n'),
                ('imported-deleter', 'from builtins import delattr as remove\nconfigure(remove)\n'),
                ('object-setter', 'install = object.__setattr__\nconfigure(install)\n'),
                ('object-deleter', 'remove = object.__delattr__\nconfigure(remove)\n')):
            with self.subTest(capability=name):
                self.inspect('escaped-capability-' + name, owner + effect, ((CRITICAL, 5),))
        for name in ('setattr', 'delattr'):
            source = f'def {name}(value):\n    return value\n' + owner
            source += f'callback = {name}\nconfigure(callback)\n'
            self.inspect('shadowed-capability-' + name, source, ())
        witness = ('def configure(install):\n'
                   '    install(Runner, "execute", lambda self, query: db.execute(query))\n' + owner
                   + 'def run(cursor, params, user, rows):\n    global db\n    db = cursor\n'
                   '    install = setattr\n    configure(install)\n'
                   '    return Runner().run(user).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'escaped-setter', witness)['rows'], 2)

    def test_record_field_sql_forwarding_is_not_a_non_database_proof(self):
        record = ('from dataclasses import dataclass\n@dataclass\nclass Request:\n    query: str\n')
        for name, body in (
                ('direct', '        return run_query(request.query)\n'),
                ('alias', '        saved = request.query\n        return run_query(saved)\n'),
                ('helper', '        return self.send(request.query)\n'
                 '    def send(self, value):\n        return run_query(value)\n')):
            owner = ('class Runner:\n    def execute(self, request):\n' + body
                     + '    def run(self, user):\n'
                     '        return self.execute(Request(f"SELECT count(*) FROM users WHERE name = \'{user}\'"))\n')
            source = 'from backend import run_query\n' + record + owner
            with self.subTest(forwarding=name):
                self.inspect('record-field-' + name, source, ((CRITICAL, len(source.splitlines())),))
            witness = ('def run_query(query):\n    return db.execute(query)\n' + record + owner
                       + 'def run(cursor, params, user, rows):\n    global db\n    db = cursor\n'
                       '    return Runner().run(user).fetchone()[0]\n')
            self.assertEqual(sqlite_witness(self.artifacts, 'record-field-' + name, witness)['rows'], 2)

    def test_constructed_and_implicit_receiver_exports_keep_sql_findings(self):
        method = ('    def execute(self, query):\n        return len(query)\n')
        sink = '        return self.execute(f"SELECT count(*) FROM users WHERE name = \'{user}\'")\n'
        cases = (
            ('stored-instance', 'class Runner:\n' + method + '    def run(self, user):\n' + sink,
             'runner = Runner()\nconfigure(runner)\nreturn runner.run(user).fetchone()[0]\n'),
            ('constructor-export', 'class Runner:\n' + method + '    def run(self, user):\n' + sink,
             'runner = configure(Runner())\nreturn runner.run(user).fetchone()[0]\n'),
            ('class-from-instance', 'class Runner:\n' + method + '    def run(self, user):\n'
             '        configure(self.__class__)\n' + sink,
             'return Runner().run(user).fetchone()[0]\n'),
            ('bound-import', 'class Runner:\n    configure = configure\n' + method
             + '    def run(self, user):\n        self.configure()\n' + sink,
             'return Runner().run(user).fetchone()[0]\n'),
            ('property', 'class Runner:\n' + method + '    @property\n    def refresh(self):\n'
             '        configure(self)\n        return None\n'
             '    def run(self, user):\n        self.refresh\n' + sink,
             'return Runner().run(user).fetchone()[0]\n'),
            ('descriptor-owner', 'class Runner:\n    hook = Descriptor()\n' + method
             + '    def run(self, user):\n' + sink,
             'return Runner().run(user).fetchone()[0]\n'),
        )
        driver = ('def configure(instance):\n    if isinstance(instance, type):\n'
                  '        instance.execute = lambda self, query: db.execute(query)\n'
                  '    else:\n        instance.execute = db.execute\n    return instance\n'
                  'class Descriptor:\n    def __set_name__(self, owner, name):\n'
                  '        owner.execute = lambda self, query: db.execute(query)\n')
        for name, owner, body in cases:
            source = ('from backend import configure, Descriptor\n' + owner
                      + 'def run(user):\n' + ''.join('    ' + line + '\n' for line in body.splitlines()))
            line = next(n for n, value in enumerate(source.splitlines(), 1) if 'return self.execute(' in value)
            with self.subTest(receiver=name):
                self.inspect('receiver-export-' + name, source, ((CRITICAL, line),))
                witness = (driver + owner + 'def run(cursor, params, user, rows):\n'
                           '    global db\n    db = cursor\n'
                           + ''.join('    ' + line + '\n' for line in body.splitlines()))
                self.assertEqual(sqlite_witness(self.artifacts, 'receiver-export-' + name, witness)['rows'], 2)
        closed = ('class Runner:\n    label = "ordinary application"\n' + method
                  + '    def run(self, user):\n' + sink
                  + 'result = Runner().run(user)\n')
        self.inspect('closed-immediate-receiver', closed, ())

    def test_kotlin_interpreter_keeps_unproved_receiver_effects_explicit(self):
        path = ROOT / 'modules/helpers/ubs_core/analyzers/narrowing_kotlin.py'
        source = path.read_text(encoding='utf-8')
        self.assertIn('def run_statement(', source)
        self.assertEqual(list(detector.find([path])), [])
        restored = source.replace('self.run_statement(', 'self.execute(').replace(
            'def run_statement(', 'def execute(')
        case = self.artifacts / 'kotlin-interpreter-restored-execute.py'
        case.write_text(restored, encoding='utf-8')
        # Remove this boundary and the naming workaround together only when
        # receiver/record effects are modeled without clearing the unsafe
        # field, descriptor and constructor witnesses above.
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'consumer call effects.*incomplete'):
            list(detector.find([case]))

    def test_class_qualified_instance_calls_need_receiver_ownership(self):
        owner = ('class Runner:\n    def execute(self, query):\n        return len(query)\n'
                 '    def run(self, user):\n'
                 '        return self.execute(f"SELECT count(*) FROM users WHERE name = \'{user}\'")\n')
        for name, extra, invocation in (
                ('direct', '', 'Runner.run(cursor, user)'),
                ('classmethod-forwarder', '    @classmethod\n    def invoke(cls, cursor, user):\n'
                 '        return cls.run(cursor, user)\n', 'Runner.invoke(cursor, user)')):
            source = owner + extra + 'def call(cursor, user):\n    return ' + invocation + '\n'
            with self.subTest(receiver=name):
                self.inspect('unbound-receiver-' + name, source, ((CRITICAL, 5),))
                witness = (owner + extra + 'def run(cursor, params, user, rows):\n'
                           '    return ' + invocation + '.fetchone()[0]\n')
                self.assertEqual(sqlite_witness(self.artifacts, 'unbound-receiver-' + name, witness)['rows'], 2)
        for decorator, receiver, parameter in (
                ('staticmethod', 'Runner', ''), ('classmethod', 'cls', 'cls, ')):
            source = (f'class Runner:\n    @{decorator}\n    def execute({parameter}query):\n'
                      '        return len(query)\n'
                      f'    @{decorator}\n    def run({parameter}user):\n'
                      f'        return {receiver}.execute(f"SELECT {{user}}")\n'
                      'result = Runner.run(user)\n')
            self.inspect('verified-class-access-' + decorator, source, ())

    def test_callback_indirection_and_implicit_calls_keep_dictionary_refusal(self):
        helper = 'def merge(keys):\n    return dict.fromkeys(key for key in keys)\n'
        callback = 'lambda keys: dict.fromkeys(key for key in keys)'
        cases = (
            ('caller-before-helper-sink', helper + 'def send(cursor):\n    cursor.execute(query)\n'
             'def run(cursor):\n    merge([Key()])\n    send(cursor)\n'),
            ('named-callback-sink', helper + 'def send(cursor):\n    cursor.execute(query)\n'
             'def run(cursor):\n    merge([Key()])\n    opaque(send, cursor)\n'),
            ('lambda-registry', f'registry = {{"merge": {callback}}}\n'
             'def run(cursor):\n    registry["merge"]([Key()])\n    cursor.execute(query)\n'),
            ('lambda-alias', f'def run(cursor):\n    fn = {callback}\n    alias = fn\n'
             '    alias([Key()])\n    cursor.execute(query)\n'),
            ('lambda-callback', f'def run(cursor):\n    opaque({callback}, [Key()])\n    cursor.execute(query)\n'),
            ('lambda-return', f'def factory():\n    return {callback}\n'
             'def run(cursor):\n    factory()([Key()])\n    cursor.execute(query)\n'),
            ('lambda-sink', helper + 'send = lambda cursor: cursor.execute(query)\n'
             'def run(cursor):\n    merge([Key()])\n    send(cursor)\n'),
            ('locals', f'def run(cursor):\n    merge = {callback}\n'
             '    fn = locals()["merge"]\n    fn([Key()])\n    cursor.execute(query)\n'),
            ('eval', f'def run(cursor):\n    merge = {callback}\n'
             '    fn = eval("merge")\n    fn([Key()])\n    cursor.execute(query)\n'),
            ('namespace-alias', 'from builtins import locals as snapshot\n'
             f'def run(cursor):\n    merge = {callback}\n'
             '    fn = snapshot()["merge"]\n    fn([Key()])\n    cursor.execute(query)\n'),
            ('eager-global-alias', f'merge = {callback}\nfn = globals()["merge"]\n'
             'def run(cursor):\n    fn([Key()])\n    cursor.execute(query)\n'),
            ('frame', 'from inspect import currentframe as frame\n'
             f'def run(cursor):\n    merge = {callback}\n'
             '    fn = frame().f_locals["merge"]\n    fn([Key()])\n    cursor.execute(query)\n'),
            ('constructor', helper + 'class Prepare:\n    def __init__(self):\n        merge([Key()])\n'
             'def run(cursor):\n    Prepare()\n    cursor.execute(query)\n'),
            ('decorator', '@invoke\n' + helper + 'def run(cursor):\n    cursor.execute(query)\n'),
        )
        for initial in ('"SELECT 1"', '"not SQL"'):
            for name, body in cases:
                with self.subTest(initial=initial, callable=name):
                    path = self.artifacts / ('callable-boundary-' + str(initial == '"SELECT 1"') + '-' + name + '.py')
                    path.write_text('query = ' + initial + '\n' + body, encoding='utf-8')
                    with self.assertRaisesRegex(detector.SQLFlowLimit, 'analysis is incomplete'):
                        list(detector.find([path]))

    def test_exclusive_list_consumers_preserve_sql_and_reject_aliases(self):
        cases = (
            ('extend-sql', '    queries = []\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
            ('extend-clean', '    queries = []\n    queries.extend("SELECT 1" for item in [user])\n    cursor.execute(queries[0])\n', ()),
            ('extend-eager-sql', '    queries = []\n    queries.extend([f"SELECT {user}"])\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
            ('extend-keeps-existing-sql', '    queries = [f"SELECT {user}"]\n    queries.extend("SELECT 1" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
            ('extend-list-constructor', '    queries = list()\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
            ('extend-alias-after', '    queries = []\n    queries.extend(f"SELECT {user}" for item in [1])\n    alias = queries\n    cursor.execute(alias[0])\n', ((CRITICAL, 5),)),
            ('extend-in-loop', '    queries = []\n    for row in rows:\n        queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 5),)),
            ('append-before-extend', '    queries = []\n    queries.append(f"SELECT {user}")\n    queries.extend("SELECT 1" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 5),)),
            ('read-item-before-extend', '    queries = ["SELECT 1"]\n    first = queries[0]\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(first)\n    cursor.execute(queries[1])\n', ((CRITICAL, 6),)),
            ('conditional-item-before-extend', '    queries = ["SELECT 1"]\n    first = queries[0] if queries else "SELECT 1"\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(first)\n    cursor.execute(queries[1])\n', ((CRITICAL, 6),)),
            ('pop-before-extend', '    queries = ["SELECT 1"]\n    first = queries.pop()\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(first)\n    cursor.execute(queries[0])\n', ((CRITICAL, 6),)),
            ('pop-captures-sql', '    queries = [f"SELECT {user}"]\n    first = queries.pop(0)\n    queries.extend("SELECT 1" for item in [1])\n    cursor.execute(first)\n', ((CRITICAL, 5),)),
            ('truth-test-before-extend', '    queries = []\n    empty = not queries\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 5),)),
            ('helper-only-iterates', '    def examine(values):\n        for value in reversed(values):\n            pass\n    queries = []\n    examine(queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 8),)),
            ('helper-only-counts', '    def examine(values):\n        return len(values)\n    queries = []\n    examine(values=queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[0])\n', ((CRITICAL, 7),)),
            ('read-only-reversed-loop', '    queries = ["SELECT 1"]\n    for query in reversed(queries):\n        cursor.execute(query)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[1])\n', ((CRITICAL, 6),)),
            ('copy-before-extend', '    queries = ["SELECT 1"]\n    copied = list(queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(copied[0])\n    cursor.execute(queries[1])\n', ((CRITICAL, 6),)),
            ('ordinary-append-lookalike', '    class Recorder:\n        def append(self, value):\n            self.value = value\n    recorder = Recorder()\n    recorder.append(f"name = {user}")\n    cursor.execute("SELECT 1")\n', ()),
            ('private-augmented-list', '    queries = []\n    queries += ["SELECT 1"]\n    queries.append(f"SELECT {user}")\n    cursor.execute(queries[1])\n', ((CRITICAL, 5),)),
            ('private-augmented-tuple', '    queries = []\n    queries += (f"SELECT {user}",)\n    cursor.execute(queries[0])\n', ((CRITICAL, 4),)),
            ('private-augmented-tuple-concat', '    values = []\n    values += (user,)\n    consume(item for item in values + [])\n', ()),
            ('distinct-unpacked-lists', '    queries, others = [], []\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[0])\n    cursor.execute("SELECT 1")\n', ((CRITICAL, 4),)),
            ('extend-deferred-sink', '    queries = []\n    queries.extend(cursor.execute(f"SELECT {user}") for item in [1])\n', ((CRITICAL, 3),)),
        )
        for name, body, expected in cases:
            with self.subTest(case=name):
                self.inspect(name, program(body), expected)
        refusals = (
            '    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    alias = queries\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    alias = queries if user else []\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    hold(queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    wrapper = {"queries": queries}\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    def alias():\n        return queries\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    class Alias:\n        value = queries\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    def alias():\n        return queries\n    queries = []\n    held = alias()\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    alias = lambda: queries\n    queries = []\n    held = alias()\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    alias = (queries for item in [1])\n    queries = []\n    held = next(alias)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    held = locals()\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    snapshot = locals\n    queries = []\n    held = snapshot()\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    qs.saved: object = queries\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    rows[0]: object = queries\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    match queries:\n        case alias:\n            pass\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    yield queries\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    queries += (f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    for alias in [queries]:\n        queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    queries.clear()\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    def examine(values):\n        return values\n    queries = []\n    examine(queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    def examine(values):\n        return iter(values)\n    queries = []\n    examine(queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    def examine(values):\n        def capture():\n            return values\n        hold(capture)\n    queries = []\n    examine(queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    def examine(values):\n        return locals()\n    queries = []\n    examine(queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    def examine(values):\n        return len(values)\n    held = examine\n    queries = []\n    examine(queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    def examine(values):\n        return len(values)\n    examine.__code__ = other_code\n    queries = []\n    examine(queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    def examine(values):\n        return len(values)\n    queries = []\n    try:\n        examine(queries)\n    except Exception:\n        pass\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
            '    queries = []\n    pending = reversed(queries)\n    queries.extend(f"SELECT {user}" for item in [1])\n    cursor.execute(queries[-1])\n',
        )
        for index, body in enumerate(refusals):
            with self.subTest(refusal=index):
                path = self.artifacts / f'list-consumer-refusal-{index}.py'
                path.write_text(program(body), encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator.*incomplete'):
                    list(detector.find([path]))
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        source = program('    queries = []\n    alias = queries\n'
                         f'    queries.append({unsafe})\n'
                         '    return cursor.execute(alias[0]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'escaped-list-append', source)['rows'], 2)
        path = self.artifacts / 'escaped-list-append.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'list mutation.*incomplete'):
            list(detector.find([path]))
        source = program('    queries = []\n    alias = queries\n'
                         f'    queries += [{unsafe}]\n'
                         '    return cursor.execute(alias[0]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'escaped-list-inplace', source)['rows'], 2)
        path = self.artifacts / 'escaped-list-inplace.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'list mutation.*incomplete'):
            list(detector.find([path]))
        for index, capture in enumerate((
                '    def alias():\n        return queries\n',
                '    alias = lambda: queries\n')):
            source = program(capture + '    queries = []\n    held = alias()\n'
                             f'    queries.extend({unsafe} for item in [1])\n'
                             '    return cursor.execute(held[0]).fetchone()[0]\n')
            with self.subTest(sqlite_alias=index):
                self.assertEqual(sqlite_witness(self.artifacts, f'late-list-alias-{index}', source)['rows'], 2)
                path = self.artifacts / f'late-list-alias-{index}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator.*incomplete'):
                    list(detector.find([path]))

    def test_private_closure_list_effects_use_call_time_values(self):
        cases = (
            ('closure-appends-argument', '    queries = []\n    def add(value):\n        queries.append(value)\n    add(f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 6),)),
            ('closure-uncalled', '    queries = ["SELECT 1"]\n    def add(value):\n        queries.append(f"SELECT {user}")\n    cursor.execute(queries[0])\n', ()),
            ('closure-late-unsafe', '    queries = []\n    query = "SELECT 1"\n    def add():\n        queries.append(query)\n    query = f"SELECT {user}"\n    add()\n    cursor.execute(queries[0])\n', ((CRITICAL, 8),)),
            ('closure-late-clean', '    queries = []\n    query = f"SELECT {user}"\n    def add():\n        queries.append(query)\n    query = "SELECT 1"\n    add()\n    cursor.execute(queries[0])\n', ()),
            ('closure-repeated-call', '    queries = []\n    def add(value):\n        queries.append(value)\n    add(f"SELECT {user}")\n    add("SELECT 1")\n    cursor.execute(queries[0])\n', ((CRITICAL, 7),)),
            ('closure-local-does-not-rebind-caller', '    queries = []\n    query = f"SELECT {user}"\n    def add(query):\n        queries.append(query)\n    add("SELECT 1")\n    cursor.execute(query)\n    cursor.execute(queries[0])\n', ((CRITICAL, 7),)),
            ('closure-parameter-does-not-restore-validation', '    queries = []\n    def add(value):\n        queries.append(value)\n    add(value=f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 6),)),
            ('closure-required-keyword-only', '    queries = []\n    def add(*, value):\n        queries.append(value)\n    add(value=f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 6),)),
            ('closure-constant-default', '    queries = []\n    def add(value="SELECT 1", *, unused=None):\n        queries.append(value)\n    add()\n    cursor.execute(queries[0])\n', ()),
            ('closure-predicate-borrow', '    queries = []\n    def add(value):\n        queries.append(value)\n    present = any(query == "SELECT 1" for query in queries)\n    add(f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 7),)),
            ('closure-predicate-tuple-unpack', '    queries = []\n    def add(value):\n        queries.append(value)\n    present = all(left < right for left, right in queries)\n    add(f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 7),)),
            ('closure-returns-sql-item', '    queries = [f"SELECT {user}"]\n    def read():\n        return queries[0]\n    cursor.execute(read())\n', ((CRITICAL, 5),)),
            ('closure-returns-clean-item', '    queries = ["SELECT 1"]\n    def read():\n        return queries[0]\n    cursor.execute(read())\n', ()),
            ('closure-mutates-and-returns-sql', '    queries = []\n    def add(value):\n        queries.append(value)\n        return f"SELECT {user}"\n    cursor.execute(add("SELECT 1"))\n', ((CRITICAL, 6),)),
            ('closure-does-not-taint-static-return', '    queries = []\n    def add(value):\n        queries.append(value)\n        return "SELECT 1"\n    cursor.execute(add(f"SELECT {user}"))\n', ()),
            ('closure-consumes-local-generator', '    queries = []\n    def add(value):\n        queries.extend(value for item in [1])\n        return len(queries)\n    add(f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 7),)),
            ('closure-after-immediate-reducer', '    queries = ["SELECT 1"]\n    def add(value):\n        queries.append(value)\n    size = sum(len(query) for query in queries)\n    add(f"SELECT {user}")\n    cursor.execute(queries[1])\n', ((CRITICAL, 7),)),
            ('closure-conditional-fresh-root', '    queries = [] if user else []\n    def add(value):\n        queries.append(value)\n    add(f"SELECT {user}")\n    cursor.execute(queries[0])\n', ((CRITICAL, 6),)),
            ('closure-finally-replaces-return', '    queries = []\n    def add():\n        try:\n            return f"SELECT {user}"\n        finally:\n            queries.append("SELECT 1")\n            return "SELECT 1"\n    cursor.execute(add())\n', ()),
            ('closure-finally-taints-return', '    queries = []\n    def add():\n        try:\n            return "SELECT 1"\n        finally:\n            queries.append("SELECT 1")\n            return f"SELECT {user}"\n    cursor.execute(add())\n', ((CRITICAL, 9),)),
            ('closure-finally-break-cancels-return', '    queries = []\n    def add():\n        for item in [1]:\n            try:\n                return f"SELECT {user}"\n            finally:\n                break\n        queries.append("SELECT 1")\n        return "SELECT 1"\n    cursor.execute(add())\n', ()),
            ('closure-in-unshadowed-comprehension', '    queries = []\n    def add(value):\n        queries.append(value)\n    unused = [add(f"SELECT {user}") for item in [1]]\n    cursor.execute(queries[0])\n', ((CRITICAL, 6),)),
            ('closure-partial-write-on-exception', '    queries = []\n    def add(value):\n        queries.append(value)\n        unknown()\n    try:\n        add(f"SELECT {user}")\n    except Exception:\n        cursor.execute(queries[0])\n', ((CRITICAL, 9),)),
            ('uncalled-closure-cannot-raise-into-outer-try', '    queries = ["SELECT 1"]\n    try:\n        def add(value):\n            queries.append(value)\n            unknown()\n    except Exception:\n        cursor.execute(f"SELECT {user}")\n', ()),
        )
        for name, body, expected in cases:
            with self.subTest(case=name):
                self.inspect(name, program(body), expected)

    def test_sequence_element_shapes_form_a_bounded_join_lattice(self):
        shapes = ((), '', 'number', 'str', 'tuple', ('tuple', ()),
                  ('tuple', 'number'), ('tuple', ('tuple', 'number')))
        join = detector.SQLInjectionAnalyzer.join_element_shapes
        for left in shapes:
            self.assertEqual(join(left, left), left)
            for right in shapes:
                self.assertEqual(join(left, right), join(right, left))
                for third in shapes:
                    self.assertEqual(join(join(left, right), third), join(left, join(right, third)))
        pair = 'tuple', ()
        previous = set()
        for _ in range(80):
            shape = detector.SQLInjectionAnalyzer.element_shape(pair)
            pair = detector.SQLInjectionAnalyzer.join_kinds(pair, ('tuple', shape))
            if pair in previous:
                break
            previous.add(pair)
        else:
            self.fail('Recursive tuple shapes did not reach a finite fixed point')

    def test_regex_offsets_require_genuine_closed_imports(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for name, prefix, setup in (
                ('direct', 'import re\n', '    match = re.search(".", user)\n'
                 '    bounds = [(match.start(), match.end())]\n'),
                ('alias', 'from re import search as locate\n', '    match = locate(".", user)\n'
                 '    bounds = [(match.start(0), match.end(0))]\n'),
                ('compiled', 'import re\n', '    pattern = re.compile(".")\n'
                 '    match = pattern.match(user)\n    bounds = [match.span()]\n'),
                ('iterator', 'import re\n', '    bounds = []\n'
                 '    for match in re.finditer(".", user[:1]):\n        bounds.append(match.span())\n'),
                ('compiled-iterator', 'import re\n', '    bounds = []\n    pattern = re.compile(".")\n'
                 '    for match in pattern.finditer(user[:1]):\n        bounds.append(match.span())\n')):
            for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = prefix + program(setup + f'    queries = [{safe}]\n'
                                          f'    for low, high in bounds:\n        queries[low:high] = [{query}]\n'
                                          '    return cursor.execute("".join(queries)).fetchone()[0]\n')
                case = 'regex-bounds-' + name + '-' + label
                with self.subTest(factory=name, value=label):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())

        prefix = ('import re\nclass Index:\n    def __index__(self):\n        return 0\n'
                  'class Match:\n    def start(self):\n        return Index()\n'
                  '    def end(self):\n        return 1\n'
                  'def tamper(module):\n    setattr(module, "search", lambda *args: Match())\n')
        for name, replacement in (
                ('member', '    re.search = lambda *args: Match()\n'),
                ('setattr', '    setattr(re, "search", lambda *args: Match())\n'),
                ('namespace', '    re.__dict__["search"] = lambda *args: Match()\n'),
                ('module-table', '    from sys import modules as loaded\n'
                 '    loaded["re"].search = lambda *args: Match()\n'),
                ('module-loader', '    from importlib import import_module as load\n'
                 '    load("re").search = lambda *args: Match()\n'),
                ('escaped', '    tamper(re)\n')):
            # Every witness executes in its own child process. An in-source
            # restoring assignment would itself disable all import proofs,
            # hiding whether the escape-specific protection actually works.
            source = prefix + program(replacement + '    match = re.search(".", user)\n'
                                      + f'    queries = [{safe}]\n'
                                      + f'    queries[match.start():match.end()] = [{unsafe}]\n'
                                      + '    return cursor.execute("".join(queries)).fetchone()[0]\n')
            case = 'regex-bounds-refusal-' + name
            with self.subTest(replacement=name):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / (case + '.py')
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'opaque index.*incomplete'):
                    list(detector.find([path]))

    def test_immutable_tuple_elements_preserve_unpacked_shapes(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for name, setup, target in (
                ('append', '    bounds = []\n    bounds.append((0, 1))\n', 'low, high'),
                ('extend', '    bounds = []\n    bounds.extend([(0, 1)])\n', 'low, high'),
                ('insert', '    bounds = []\n    bounds.insert(0, (0, 1))\n', 'low, high'),
                ('slice', '    bounds = []\n    bounds[:] = [(0, 1)]\n', 'low, high'),
                ('augmented', '    bounds = []\n    bounds += [(0, 1)]\n', 'low, high'),
                ('concat', '    bounds = [] + [(0, 1)]\n', 'low, high'),
                ('repeat', '    bounds = [(0, 1)] * 1\n', 'low, high'),
                ('comprehension', '    bounds = [(index, index + 1) for index in range(1)]\n', 'low, high'),
                ('loop', '    bounds = []\n    for index in range(1):\n        bounds.append((index, index + 1))\n', 'low, high'),
                ('nested', '    bounds = []\n    bounds.append(((0,), (1,)))\n', '(low,), (high,)'),
                ('immutable-snapshot', '    class Index:\n        def __index__(self):\n            return 0\n'
                 '    bounds = [(0, 1)]\n    pair = bounds[0]\n    bounds[0] = (Index(), 1)\n'
                 '    bounds = [pair]\n', 'low, high'),
                ('branch', '    bounds = []\n    if user:\n        bounds.append((0, 1))\n', 'low, high')):
            for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program(setup + f'    queries = [{safe}]\n'
                                 f'    for {target} in bounds:\n        queries[low:high] = [{query}]\n'
                                 '    return cursor.execute("".join(queries)).fetchone()[0]\n')
                case = 'tuple-bounds-' + name + '-' + label
                with self.subTest(shape=name, value=label):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())

        for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
            source = program('    shape = ()\n    count = 0\n    while count < 2:\n'
                             '        shape = (shape,)\n        count += 1\n'
                             f'    return cursor.execute({query}).fetchone()[0]\n')
            case = 'tuple-recursive-shape-' + label
            with self.subTest(recursive_shape=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                self.inspect(case, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())

        # Shapes describe types, never SQL safety. Tuple-valued list elements
        # must preserve their text provenance through indexing and unpacking.
        for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
            source = program('    records = []\n' + f'    records.append(({query},))\n'
                             '    for (query,) in records:\n'
                             '        return cursor.execute(query).fetchone()[0]\n')
            case = 'tuple-text-' + label
            with self.subTest(text=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                self.inspect(case, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())

        for name, prefix, setup in (
                ('opaque-index', 'class Index:\n    def __index__(self):\n        return 0\n',
                 '    bounds = []\n    bounds.append((Index(), 1))\n'),
                ('escaped-outer', '', '    bounds = [(0, 1)]\n    alias = bounds\n'
                 '    alias[0] = (0, 1)\n')):
            source = prefix + program(setup + f'    queries = [{safe}]\n'
                                      f'    for low, high in bounds:\n        queries[low:high] = [{unsafe}]\n'
                                      '    return cursor.execute("".join(queries)).fetchone()[0]\n')
            case = 'tuple-bounds-refusal-' + name
            with self.subTest(refusal=name):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / (case + '.py')
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'opaque index.*incomplete'):
                    list(detector.find([path]))

    def test_closed_numeric_list_regions_preserve_alias_types(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for name, setup in (
                ('stack', '    frames = [[0, True]]\n    frame = frames[-1]\n'
                 '    frames.append([0, False])\n    selected = frames.pop()\n'
                 '    selected[0] += 1\n    frame[0] = selected[0]\n    frame[1] = False\n'),
                ('deep', '    frames = [[[0, True]]]\n    frame = frames[-1][0]\n'
                 '    frame[0] += 1\n    frame[1] = False\n'),
                ('named', '    frames = [[0, True]]\n    parent = frames\n'
                 '    frame = parent[0]\n    frame[0] += 1\n'),
                ('conditional', '    frames = [[0, True]]\n'
                 '    frame = frames[0] if user else frames[-1]\n    frame[0] += 1\n'),
                ('shadowed-parameter', '    frames = [[0, True]]\n    frame = frames[0]\n'
                 '    def unused(frame):\n        return frame\n    frame[0] += 1\n'),
                ('streaming', '    frames = [[0, True]]\n'
                 '    for item in (value for value in [1]):\n        frame = frames[0]\n'
                 '        frame[0] += item\n')):
            for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program(setup + f'    queries = [{safe}, {query}]\n'
                                 '    return cursor.execute(queries[frame[0]]).fetchone()[0]\n')
                case = 'numeric-region-' + name + '-' + label
                with self.subTest(region=name, value=label):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())
        for name, mutation in (
                ('item-write', f'    frame = frames[0]\n    frame[0] = {unsafe}\n'),
                ('append', f'    frame = frames[0]\n    frame.append({unsafe})\n'
                 '    frames[0][0] = frame[-1]\n'),
                ('borrowed-child', '    mutate(frames[0])\n'),
                ('copied-parent', '    copied = list(frames)\n    mutate(copied[0])\n'),
                ('iterator-child', '    copied = [child for child in frames]\n    mutate(copied[0])\n'),
                ('sliced-parent', '    copied = frames[:]\n    mutate(copied[0])\n'),
                ('named-parent', '    copied = frames\n    mutate(copied[0])\n'),
                ('conditional-child', '    frame = frames[0] if user else frames[0]\n    mutate(frame)\n'),
                ('boolean-child', '    frame = frames[0] or frames[0]\n    mutate(frame)\n'),
                ('joined-child', '    if user:\n        frame = frames[0]\n'
                 '    else:\n        frame = frames[0]\n    mutate(frame)\n'),
                ('maybe-child', '    if user:\n        frame = frames[0]\n    mutate(frame)\n'),
                ('rebound-child', '    frame = frames[0]\n    if not user:\n        frame = []\n'
                 '    mutate(frame)\n'),
                ('comprehension-result', '    copied = [frames[0] for unused in [1]]\n    mutate(copied[0])\n'),
                ('assert-message', '    frame = frames[0]\n    try:\n        assert False, frame\n'
                 '    except AssertionError as problem:\n        mutate(problem.args[0])\n'),
                ('tuple-parent', '    copied = (frames[0],)\n    mutate(copied[0])\n'),
                ('deferred-child', '    def later():\n        mutate(frames[0])\n    later()\n')):
            source = program('    def mutate(values):\n' + f'        values[0] = {unsafe}\n'
                             '    frames = [[0, True]]\n' + mutation
                             + '    return cursor.execute(frames[0][0]).fetchone()[0]\n')
            case = 'numeric-region-refusal-' + name
            with self.subTest(escape=name):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / (case + '.py')
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'incomplete'):
                    list(detector.find([path]))

    def test_local_list_parameters_transfer_effects_without_exporting_aliases(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for name, helper, setup, call, result in (
                ('append', '    def write(output, value):\n        output.append(value)\n',
                 '    queries = []\n', 'write(queries, {query})', 'queries[0]'),
                ('indexed', '    def write(output, value):\n        output[0] = value\n',
                 f'    queries = [{safe}]\n', 'write(queries, {query})', 'queries[0]'),
                ('range', '    def write(output, value, stop):\n'
                 '        for position in range(stop):\n            output[position] = value\n',
                 f'    queries = [{safe}]\n', 'write(queries, {query}, min(1, len(queries)))', 'queries[0]'),
                ('keyword', '    def write(*, output, value):\n        output.append(value)\n',
                 '    queries = []\n', 'write(value={query}, output=queries)', 'queries[0]'),
                ('distinct', '    def write(output, other, value):\n'
                 '        output.append(value)\n        other.append(value)\n',
                 '    queries = []\n    other = []\n', 'write(queries, other, {query})', 'other[0]'),
                ('repeat', '    def write(output, value):\n        output.append(value)\n        return "ok"\n',
                 '    queries = []\n', f'write(queries, {safe})\n    write(queries, {{query}})', 'queries[-1]'),
                ('caught', '    def write(output, value):\n'
                 '        try:\n            output.append(value)\n            1 / 0\n'
                 '        except ZeroDivisionError:\n            pass\n',
                 '    queries = []\n', 'write(queries, {query})', 'queries[0]'),
                ('scalar-return', '    def write(output, value):\n'
                 '        output.append(value)\n        return output[-1]\n',
                 '    queries = []\n', 'selected = write(queries, {query})', 'selected'),
                ('index-return', '    def write(output, value):\n'
                 '        output.append(value)\n        return 0\n',
                 '    queries = []\n', 'selected = write(queries, {query})', 'queries[selected]')):
            for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program(helper + setup + '    ' + call.format(query=query) + '\n'
                                 + f'    return cursor.execute({result}).fetchone()[0]\n')
                case = 'list-parameter-' + name + '-' + label
                with self.subTest(effect=name, value=label):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())

        for name, helper, setup, call, result, reason in (
                ('export', '    def write(output, value):\n'
                 '        output.append(value)\n        return output\n',
                 '    queries = []\n', 'alias = write(queries, {query})', 'alias[0]', 'parameter escape'),
                ('duplicate', '    def write(output, other, value):\n'
                 '        output.append(value)\n        other.append(value)\n',
                 '    queries = []\n', 'write(queries, queries, {query})', 'queries[0]', 'parameter aliases'),
                ('readonly-alias', '    def write(output, other, value):\n'
                 '        output.append(value)\n        return other[0]\n',
                 f'    queries = [{safe}]\n', 'write(queries, queries, {query})', 'queries[-1]', 'parameter aliases'),
                ('rebind', '    def write(output, value):\n'
                 '        output.append(value)\n        output = []\n',
                 '    queries = []\n', 'write(queries, {query})', 'queries[0]', 'parameter escape'),
                ('unknown-producer', '    def produce():\n        return ' + unsafe + '\n'
                 '    def write(output, value):\n        output.append(produce())\n',
                 '    queries = []\n', f'write(queries, {safe})', 'queries[0]', 'consumer call effects'),
                ('maybe-defined', '    if user:\n        def write(output, value):\n            output.append(value)\n',
                 '    queries = []\n', 'write(queries, {query})', 'queries[0]', 'definition order'),
                ('active-iteration', '    def write(output, value):\n        output[0] = value\n',
                 f'    queries = [{safe}]\n', 'for unused in queries:\n        write(queries, {query})\n        break',
                 'queries[0]', 'mutation during list iteration'),
                ('mutable-child', '    def write(output, value):\n'
                 '        output.append([value])\n        return output[0]\n',
                 '    queries = []\n', 'alias = write(queries, {query})', 'alias[0]', 'child aliases')):
            source = program(helper + setup + '    ' + call.format(query=unsafe) + '\n'
                             + f'    return cursor.execute({result}).fetchone()[0]\n')
            case = 'list-parameter-refusal-' + name
            with self.subTest(refusal=name):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / (case + '.py')
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, reason + '.*incomplete'):
                    list(detector.find([path]))

        source = program('    def write(output, token, value):\n'
                         '        output[0] = value\n        return output[0]\n'
                         + f'    queries = [{safe}]\n'
                         + f'    selected = write(queries, (queries := []), {unsafe})\n'
                         + '    return cursor.execute(selected).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'list-parameter-rebound-argument', source)['rows'], 2)
        path = self.artifacts / 'list-parameter-rebound-argument.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'captured binding changed.*incomplete'):
            list(detector.find([path]))

        source = ('class DeferredCursor:\n    def __init__(self, cursor):\n        self.cursor = cursor\n'
                  '    def execute(self, queries, token):\n        return self.cursor.execute(queries[0])\n'
                  + program('    def write(output, value):\n        output[0] = value\n'
                            + f'    queries = [{safe}]\n'
                            + f'    return DeferredCursor(cursor).execute(queries, write(queries, {unsafe})).fetchone()[0]\n'))
        self.assertEqual(sqlite_witness(self.artifacts, 'list-parameter-earlier-argument', source)['rows'], 2)
        path = self.artifacts / 'list-parameter-earlier-argument.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'mutation during argument evaluation.*incomplete'):
            list(detector.find([path]))

        source = program('    def opaque():\n        return None\n'
                         '    def write(output, value, receiver):\n        output.append(value)\n'
                         '        result = receiver.execute(value).fetchone()[0]\n'
                         '        opaque()\n        return result\n'
                         + '    queries = []\n' + f'    return write(queries, {unsafe}, cursor)\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'list-parameter-partial', source)['rows'], 2)
        path = self.artifacts / 'list-parameter-partial.py'
        path.write_text(source, encoding='utf-8')
        found = detector.find([path])
        first = next(found)
        self.assertEqual((first[0], first[1], first[2], first[3]), (CRITICAL, path, 6, 1))
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'consumer call effects.*incomplete'):
            list(found)

        source = program(f'    queries = [{safe}]\n'
                         '    def read():\n        return queries[0]\n'
                         '    class Holder:\n        queries: str\n'
                         '        def mutate(self, value):\n            queries[0] = value\n'
                         + f'    Holder().mutate({unsafe})\n'
                         + '    return cursor.execute(read()).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'list-parameter-class-scope', source)['rows'], 2)
        path = self.artifacts / 'list-parameter-class-scope.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure list ownership.*incomplete'):
            list(detector.find([path]))

    def test_closed_primitive_record_frames_keep_column_shapes(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for name, setup in (
                ('direct', '    frames = [["code", 0]]\n    frames[-1][1] += 1\n    frame = frames[-1]\n'),
                ('named', '    frames = [["code", 0]]\n    frame = frames[0]\n'
                 '    frame[0] = "expression"\n    frame[1] += 1\n'),
                ('pop', '    frames = [["code", 0]]\n    frames.append(["template", 0])\n'
                 '    frame = frames.pop()\n    frame[1] += 1\n'),
                ('extend', '    frames = [["code", 0]]\n    frames.extend([["template", 0]])\n'
                 '    frame = frames[-1]\n    frame[1] += 1\n'),
                ('multiple', '    frames = [["code", 0], ["expression", 0]]\n'
                 '    frame = frames[-1]\n    frame[1] += 1\n'),
                ('negative-field', '    frames = [["code", 0]]\n'
                 '    frame = frames[0]\n    frame[-1] += 1\n')):
            for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program(setup + f'    queries = [{safe}, {query}]\n'
                                 '    return cursor.execute(queries[frame[1]]).fetchone()[0]\n')
                case = 'primitive-frame-' + name + '-' + label
                with self.subTest(frame=name, value=label):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())

        source = program(f'    frames = [[{safe}, 0]]\n    frame = frames[0]\n'
                         '    frame[1] = len(user)\n'
                         '    return cursor.execute(frame[0]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'primitive-frame-static-tag', source)['rows'], 1)
        self.inspect('primitive-frame-static-tag', source, ())

        for name, mutation, result in (
                ('numeric-field-text', f'    frame[1] = {unsafe}\n', 'frame[1]'),
                ('tag-field-text', f'    frame[0] = {unsafe}\n', 'frame[0]'),
                ('append-field', f'    frame.append({unsafe})\n', 'frame[-1]'),
                ('delete-field', f'    del frame[0]\n    frame.append({unsafe})\n', 'frame[1]'),
                ('pop-field', f'    frame.pop()\n    frame.append({unsafe})\n', 'frame[-1]'),
                ('borrowed-row', '    mutate(frame)\n', 'frame[1]'),
                ('indexed-row', '    mutate(frames[0])\n', 'frames[0][1]'),
                ('copied-parent', '    clone = list(frames)\n    mutate(clone[0])\n', 'frame[1]')):
            source = program('    def mutate(values):\n' + f'        values[1] = {unsafe}\n'
                             + '    frames = [["code", 0]]\n    frame = frames[0]\n' + mutation
                             + f'    return cursor.execute({result}).fetchone()[0]\n')
            case = 'primitive-frame-refusal-' + name
            with self.subTest(refusal=name):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / (case + '.py')
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'incomplete'):
                    list(detector.find([path]))

        source = program('    frames = [["code", 0]]\n    frame = frames[0]\n    frame[1 + 0] += 1\n'
                         + f'    queries = [{safe}, {unsafe}]\n'
                         + '    return cursor.execute(queries[frame[1]]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'primitive-frame-opaque-field', source)['rows'], 2)
        path = self.artifacts / 'primitive-frame-opaque-field.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'record field index.*incomplete'):
            list(detector.find([path]))

    def test_recursive_sibling_groups_keep_shared_cells_and_definition_order(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for name, helpers, call, result in (
                ('writes', '    def first(value, again):\n        if again:\n            second(value, again - 1)\n'
                 '        else:\n            queries.append(value)\n'
                 '    def second(value, again):\n        if again:\n            first(value, again - 1)\n'
                 '        else:\n            queries.append(value)\n', 'first({query}, 3)', 'queries[-1]'),
                ('returns', '    def first(value, again):\n        if again:\n            return second(value, again - 1)\n'
                 '        queries.append(None)\n        return value\n'
                 '    def second(value, again):\n        if again:\n            return first(value, again - 1)\n'
                 '        queries.append(None)\n        return value\n', 'first({query}, 3)', 'selected'),
                ('prior-leaf', '    def add(value):\n        queries.append(value)\n'
                 '    def first(value, again):\n        if again:\n            second(value, again - 1)\n'
                 '        else:\n            add(value)\n'
                 '    def second(value, again):\n        if again:\n            first(value, again - 1)\n'
                 '        else:\n            add(value)\n', 'first({query}, 3)', 'queries[-1]'),
                ('three-members', '    def first(value, again):\n        if again:\n            second(value, again - 1)\n'
                 '        else:\n            queries.append(value)\n'
                 '    def second(value, again):\n        if again:\n            third(value, again - 1)\n'
                 '        else:\n            queries.append(value)\n'
                 '    def third(value, again):\n        if again:\n            first(value, again - 1)\n'
                 '        else:\n            queries.append(value)\n', 'first({query}, 3)', 'queries[-1]')):
            for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program('    queries = []\n' + helpers + '    selected = ' + call.format(query=query) + '\n'
                                 + f'    return cursor.execute({result}).fetchone()[0]\n')
                case = 'recursive-siblings-' + name + '-' + label
                with self.subTest(group=name, value=label):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())

        for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
            source = program('    queries = []\n    def first():\n        queries.append(None)\n        return second()\n'
                             '    def second():\n        queries.append(None)\n        return first()\n'
                             '    try:\n        first()\n    except RecursionError:\n        pass\n'
                             + f'    return cursor.execute({query}).fetchone()[0]\n')
            case = 'recursive-siblings-bottom-' + label
            with self.subTest(bottom=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                self.inspect(case, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())

        for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
            source = program('    queries = []\n    def add(value):\n        cursor.execute(value)\n'
                             '        queries.append(None)\n'
                             '    def first(value, depth):\n        if depth:\n            second(value, depth - 1)\n'
                             '        else:\n            add(value)\n'
                             '    def second(value, depth):\n        if depth:\n            first(value, depth - 1)\n'
                             '        else:\n            add(value)\n'
                             + f'    first({query}, 3)\n    return cursor.fetchone()[0]\n')
            case = 'recursive-siblings-leaf-sink-' + label
            with self.subTest(leaf_sink=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                self.inspect(case, source, ((CRITICAL, 4),) if rows == 2 else ())

        source = program('    queries = []\n    def first():\n        queries.append(None)\n'
                         + f'        cursor.execute({unsafe})\n        return second()\n'
                         + '    def second():\n        queries.append(None)\n        return first()\n'
                         + f'    return cursor.execute({safe}).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'recursive-siblings-uncalled', source)['rows'], 1)
        self.inspect('recursive-siblings-uncalled', source, ())

        for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
            source = program('    queries = []\n    def add(value):\n        queries.append(value)\n'
                             '        1 / 0\n    try:\n' + f'        add({safe})\n'
                             + '    except ZeroDivisionError:\n        pass\n'
                             + f'    queries.append({query})\n'
                             + '    return cursor.execute(queries[-1]).fetchone()[0]\n')
            case = 'sealed-exception-retains-private-list-' + label
            with self.subTest(exception_ownership=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                self.inspect(case, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())

        for name, helpers, invocation in (
                ('early-call', '    def first(value):\n        queries.append(value)\n        return second(value)\n'
                 f'    try:\n        first({unsafe})\n    except NameError:\n        pass\n'
                 '    def second(value):\n        if False:\n            first(value)\n        return value\n', ''),
                ('conditional-definition', '    def first(value):\n        queries.append(value)\n        return second(value)\n'
                 '    if user:\n        def second(value):\n            if False:\n                first(value)\n'
                 '            return value\n', f'    first({unsafe})\n'),
                ('escaped-helper', '    def first(value, again):\n        if again:\n            second(value, False)\n'
                 '        else:\n            queries.append(value)\n'
                 '    def second(value, again):\n        if again:\n            first(value, False)\n'
                 '        else:\n            queries.append(value)\n    exported = first\n', f'    first({unsafe}, True)\n'),
                ('shadowed-cell', f'    query = {unsafe}\n'
                 '    def first(value, again):\n        if again:\n            second(value, False)\n'
                 '        else:\n            queries.append(query)\n'
                 '    def second(query, again):\n        first(query, False)\n', f'    first({safe}, True)\n')):
            source = program('    queries = []\n' + helpers + invocation
                             + '    return cursor.execute(queries[-1]).fetchone()[0]\n')
            case = 'recursive-siblings-refusal-' + name
            with self.subTest(refusal=name):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / (case + '.py')
                path.write_text(source, encoding='utf-8')
                reason = ('list mutation aliasing' if name == 'shadowed-cell' else
                          '(?:closure list ownership|recursive sibling definition order)')
                with self.assertRaisesRegex(detector.SQLFlowLimit, '^SQL ' + reason + '.*incomplete$'):
                    list(detector.find([path]))

    def test_sibling_closures_preserve_lexical_cells_and_sql_effects(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for label, helpers in (
                ('forward', '    def add(value):\n        queries.append(value)\n'
                 '    def forward(text):\n        add(text)\n'),
                ('two-hops', '    def add(value):\n        queries.append(value)\n'
                 '    def relay(item):\n        add(item)\n'
                 '    def forward(text):\n        relay(text)\n'),
                ('return', '    def add(value):\n        queries.append(value)\n        return value\n'
                 '    def forward(text):\n        return add(text)\n')):
            for value, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program('    queries = []\n' + helpers + f'    forward({query})\n'
                                 + '    return cursor.execute(queries[-1]).fetchone()[0]\n')
                line = next(index for index, text in enumerate(source.splitlines(), 1)
                            if 'return cursor.execute' in text)
                case = f'sibling-{label}-{value}'
                with self.subTest(helper=label, value=value):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, line),) if rows == 2 else ())
        for label, shadow in (
                ('direct-shadow', '    def forward(query):\n        add()\n'),
                ('transitive-shadow', '    def relay():\n        add()\n'
                 '    def forward(query):\n        relay()\n')):
            source = program('    queries = []\n' + f'    query = {unsafe}\n'
                             + '    def add():\n        queries.append(query)\n'
                             + shadow + f'    forward({safe})\n'
                             + '    return cursor.execute(queries[0]).fetchone()[0]\n')
            case = 'sibling-' + label
            with self.subTest(refusal=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / (case + '.py')
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure.*incomplete'):
                    list(detector.find([path]))

        for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
            source = program('    queries = []\n    def hidden(value):\n'
                             + '        queries.append(cursor.execute(value).fetchone()[0])\n'
                             + f'    hidden({query})\n    return queries[0]\n')
            case = 'sibling-call-site-sink-' + label
            with self.subTest(call_site=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                self.inspect(case, source, ((CRITICAL, 4),) if rows == 2 else ())
        source = program('    queries = []\n    def hidden():\n        queries.append(None)\n'
                         + f'        cursor.execute({unsafe})\n'
                         + f'    return cursor.execute({safe}).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'sealed-helper-not-called', source)['rows'], 1)
        self.inspect('sealed-helper-not-called', source, ())

    def test_recursive_void_closure_list_summaries_reach_a_fixed_point(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        cases = (
            ('recursive-parameter', '    queries = []\n    def add(value, depth):\n'
             '        if depth:\n            add(value, depth - 1)\n'
             '        else:\n            queries.append(value)\n'
             f'    add({unsafe}, 3)\n', 2),
            ('recursive-transformed-input', '    queries = []\n    def add(value, again):\n'
             f'        if again:\n            add({unsafe}, False)\n'
             '        else:\n            queries.append(value)\n'
             f'    add({safe}, True)\n', 2),
            ('recursive-tree', '    queries = []\n    def add(values):\n'
             '        for value in values:\n            if isinstance(value, list):\n'
             '                add(value)\n            else:\n                queries.append(value)\n'
             f'    add([[{unsafe}]])\n', 2),
            ('recursive-clean', '    queries = []\n    def add(value, depth):\n'
             '        if depth:\n            add(value, depth - 1)\n'
             '        else:\n            queries.append(value)\n'
             f'    add({safe}, 3)\n', 1),
            ('recursive-exception-write', '    queries = []\n    def add(again):\n'
             '        if again:\n            add(False)\n        else:\n'
             f'            queries.append({unsafe})\n            raise ValueError("stop")\n'
             '    try:\n        add(True)\n    except ValueError:\n        pass\n', 2),
            ('uncalled-recursive-closure', f'    queries = [{safe}]\n    def add(depth):\n'
             '        if depth:\n            add(depth - 1)\n        else:\n'
             f'            queries.append({unsafe})\n', 1),
        )
        for name, body, rows in cases:
            source = program(body + '    return cursor.execute(queries[-1]).fetchone()[0]\n')
            with self.subTest(case=name):
                self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], rows)
                self.inspect(name, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())
        source = program(cases[0][1] + '    cursor.execute(queries[-1])\n')
        path = self.artifacts / 'recursive-budget.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'budget.*incomplete'):
            list(detector.find([path], max_steps=20))

    def test_recursive_return_summaries_preserve_values_and_bottom_edges(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for label, recursive_return, base in (
                ('tail', 'render(value, False)', '        queries.append(value)\n        return value\n'),
                ('join', '"".join([render(value, False)])', '        queries.append(value)\n        return value\n'),
                ('finally', 'render(value, False)', '        try:\n            return value\n'
                 '        finally:\n            queries.append(value)\n')):
            for value, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program('    queries = []\n    def render(value, again):\n'
                                 + f'        if again:\n            return {recursive_return}\n'
                                 + base + f'    query = render({query}, True)\n'
                                 + '    return cursor.execute(query).fetchone()[0]\n')
                line = next(index for index, text in enumerate(source.splitlines(), 1)
                            if 'return cursor.execute' in text)
                case = f'recursive-return-{label}-{value}'
                with self.subTest(returned=label, value=value):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, line),) if rows == 2 else ())
        for label, expression in (
                ('comprehension-zero', '[spin() for item in rows]'),
                ('dictionary-zero', '{item: spin() for item in rows}'),
                ('boolean-bypass', '(not user) and spin()'),
                ('conditional-bypass', 'spin() if not user else None')):
            source = program('    queries = []\n    def spin():\n        queries.append(None)\n'
                             + '        return spin()\n'
                             + f'    unused = {expression}\n'
                             + f'    return cursor.execute({unsafe}).fetchone()[0]\n')
            line = next(index for index, text in enumerate(source.splitlines(), 1)
                        if 'return cursor.execute' in text)
            case = 'recursive-bottom-' + label
            with self.subTest(bypass=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                self.inspect(case, source, ((CRITICAL, line),))
        source = program('    queries = []\n    def fail(value, again):\n'
                         + '        if again:\n            return fail(value, False)\n'
                         + '        queries.append(value)\n        raise ValueError("stop")\n'
                         + f'    try:\n        fail({unsafe}, True)\n'
                         + '    except ValueError:\n        pass\n'
                         + '    return cursor.execute(queries[-1]).fetchone()[0]\n')
        line = next(index for index, text in enumerate(source.splitlines(), 1)
                    if 'return cursor.execute' in text)
        self.assertEqual(sqlite_witness(self.artifacts, 'recursive-raise-effects', source)['rows'], 2)
        self.inspect('recursive-raise-effects', source, ((CRITICAL, line),))

        source = program('    queries = []\n    def spin():\n        queries.append(None)\n'
                         + '        return spin()\n    def ignore(values):\n        return None\n'
                         + '    ignore(spin() for item in [1])\n'
                         + f'    return cursor.execute({unsafe}).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'recursive-opaque-drain-may-not-run', source)['rows'], 2)
        path = self.artifacts / 'recursive-opaque-drain-may-not-run.py'
        path.write_text(source, encoding='utf-8')
        # The lazy capture may revoke private ownership before the probe
        # reaches its nonreturning edge. Either boundary must stay incomplete.
        with self.assertRaisesRegex(detector.SQLFlowLimit,
                                    r'^SQL (?:closure list ownership|generator projection completion).*incomplete$'):
            list(detector.find([path]))

    def test_recursive_bottom_preserves_statement_bypasses(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        prefix = '    queries = []\n    def spin():\n        queries.append(None)\n        return spin()\n'
        for name, body, optimized in (
                ('match-miss', '    match user:\n        case None if spin():\n            pass\n'
                 '        case _:\n            pass\n', False),
                ('assert-test-optimized', '    assert spin()\n', True),
                ('assert-message-optimized', '    assert False, spin()\n', True),
                ('with-suppressed-setup', '    class Suppress:\n        def __enter__(self):\n'
                 '            return None\n        def __exit__(self, *exc):\n            return True\n'
                 '    with Suppress(), spin():\n        pass\n', False),
                ('earlier-handler', '    try:\n        raise ValueError("stop")\n'
                 '    except ValueError:\n        pass\n    except spin():\n        pass\n', False)):
            source = program(prefix + body + f'    return cursor.execute({unsafe}).fetchone()[0]\n')
            line = len(source.splitlines())
            with self.subTest(bypass=name):
                witness = sqlite_witness(self.artifacts, 'recursive-bottom-' + name, source, optimize=optimized)
                self.assertEqual(witness['rows'], 2)
                self.assertEqual(witness['optimize'], int(optimized))
                self.inspect('recursive-bottom-' + name, source, ((CRITICAL, line),))
        source = program(prefix + '    try:\n        match user:\n'
                         '            case _ if spin():\n                pass\n'
                         '            case _:\n                pass\n'
                         '    except RecursionError:\n'
                         '        return cursor.execute("SELECT count(*) FROM users WHERE name = \'alice\'").fetchone()[0]\n'
                         + f'    return cursor.execute({unsafe}).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'recursive-bottom-no-pattern-miss', source)['rows'], 1)
        self.inspect('recursive-bottom-no-pattern-miss', source, ())

    def test_private_closure_scalar_cells_transfer_lexical_effects(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for label, initial, declaration, invocation in (
                ('direct', safe, '    def add(value):\n        nonlocal query\n'
                 '        query = value\n        queries.append(value)\n', 'add(VALUE)'),
                ('overwrite', unsafe, '    def add(value):\n        nonlocal query\n'
                 '        query = value\n        queries.append(value)\n', 'add(VALUE)'),
                ('recursive', safe, '    def add(value, depth):\n        nonlocal query\n'
                 '        if depth:\n            add(value, depth - 1)\n'
                 '        else:\n            query = value\n        queries.append(value)\n', 'add(VALUE, 2)'),
                ('forwarded', safe, '    def add(value):\n        nonlocal query\n'
                 '        query = value\n        queries.append(value)\n'
                 '    def forward(value):\n        add(value)\n', 'forward(VALUE)'),
                ('argument-rebind', safe, '    def add(value):\n        nonlocal query\n'
                 '        query = value\n        queries.append(value)\n',
                 'add((add := None) or VALUE)'),
                ('exception-prefix', safe, '    def add(value, depth):\n        nonlocal query\n'
                 '        if depth:\n            add(value, depth - 1)\n'
                 '        else:\n            query = value\n        queries.append(value)\n'
                 '        raise ValueError("stop")\n',
                 'try:\n        add(VALUE, 1)\n    except ValueError:\n        pass'),
                ('copied-iterator', safe, '    def add(value):\n        nonlocal query\n'
                 '        query = value\n        queries.append(value)\n'
                 '        snapshot = tuple(item for item in queries[:])\n'
                 '        return snapshot\n', 'add(VALUE)'),
                ('cleanup-lifetime', safe, '    def add(value, depth):\n        nonlocal query\n'
                 '        if depth:\n            add(value, depth - 1)\n'
                 '        query = value\n        queries.append(value)\n'
                 '        snapshot = tuple(item for item in queries[:])\n'
                 '        return snapshot\n',
                 'try:\n        add(VALUE, 1)\n    finally:\n        add = None'),
                ('primitive-join', safe, '    counter = None\n'
                 '    def add(value, depth):\n        nonlocal query, counter\n'
                 '        counter = len(queries)\n        query = value\n'
                 '        if depth:\n            add(value, depth - 1)\n'
                 '        queries.append(value)\n', 'add(VALUE, 2)')):
            for value, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program('    queries = []\n' + f'    query = {initial}\n' + declaration
                                 + '    ' + invocation.replace('VALUE', query) + '\n'
                                 + '    return cursor.execute(query).fetchone()[0]\n')
                case = f'closure-cell-{label}-{value}'
                with self.subTest(case=case):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, len(source.splitlines())),) if rows == 2 else ())

        source = program(f'    query = {safe}\n    queries = []\n'
                         '    def add(value):\n        nonlocal query\n        query = value\n'
                         '        queries.append(value)\n'
                         '    return cursor.execute(query).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'closure-cell-uncalled', source)['rows'], 1)
        self.inspect('closure-cell-uncalled', source, ())

        source = program(f'    query = {safe}\n    queries = []\n'
                         '    def add(value):\n        nonlocal query\n        query = value\n'
                         '        queries.append(value)\n    add = None\n'
                         f'    try:\n        add({unsafe})\n    except TypeError:\n        pass\n'
                         '    return cursor.execute(query).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'closure-cell-cleared-before-call', source)['rows'], 1)
        self.inspect('closure-cell-cleared-before-call', source, ())

        for label, body in (
                ('mutable-input', '    query = []\n    queries = []\n'
                 '    def add(value):\n        nonlocal query\n        query.append(value)\n'
                 '        queries.append(value)\n' + f'    add({unsafe})\n'
                 '    return cursor.execute(query[0]).fetchone()[0]\n'),
                ('mutable-rebind', '    query = "SELECT 1"\n    queries = []\n'
                 '    def add(value):\n        nonlocal query\n        query = [value]\n'
                 '        queries.append(value)\n' + f'    add({unsafe})\n'
                 '    return cursor.execute(query[0]).fetchone()[0]\n'),
                ('deleted-cell', '    query = "SELECT 1"\n    saved = []\n'
                 '    def add(value):\n        nonlocal query\n        del query\n'
                 '        saved.append(value)\n' + f'    add({unsafe})\n'
                 '    return cursor.execute(saved[0]).fetchone()[0]\n'),
                ('escaped-callable', '    query = "SELECT 1"\n    queries = []\n'
                 '    def add(value):\n        nonlocal query\n        query = value\n'
                 '        queries.append(value)\n    alias = add\n'
                 f'    alias({unsafe})\n    add = None\n'
                 '    return cursor.execute(query).fetchone()[0]\n'),
                ('conditional-lifetime', '    query = "SELECT 1"\n    queries = []\n'
                 '    def add(value):\n        nonlocal query\n        query = value\n'
                 '        queries.append(value)\n    if not user:\n        add = None\n'
                 f'    add({unsafe})\n    return cursor.execute(query).fetchone()[0]\n'),
                ('conditional-argument-rebind', '    query = "SELECT 1"\n    queries = []\n'
                 '    def add(value):\n        nonlocal query\n        query = value\n'
                 '        queries.append(value)\n    if not user:\n        add = None\n'
                 f'    add((add := None) or {unsafe})\n'
                 '    return cursor.execute(query).fetchone()[0]\n')):
            source = program(body)
            case = 'closure-cell-refusal-' + label
            with self.subTest(refusal=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / (case + '.py')
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure.*incomplete'):
                    list(detector.find([path]))

        # A closure created before allocation can still retain the future
        # cell. Absence of a current private list cannot authorize a clean
        # call after any supported outer-storage allocation form.
        for label, allocation in (
                ('literal', '    queries = []\n'),
                ('comprehension', '    queries = [item for item in []]\n'),
                ('constructor', '    queries = list()\n'),
                ('repetition', '    queries = [] * 1\n'),
                ('concatenation', '    queries = [] + []\n'),
                ('slice', '    queries = ["SELECT 1"][:]\n'),
                ('conditional', '    queries = [] if user else []\n'),
                ('unpacking', '    unused, queries = (None, [])\n'),
                ('annotated', '    queries: list = []\n')):
            source = program('    def add(value):\n        queries.append(value)\n' + allocation
                             + f'    add({unsafe})\n'
                             + '    return cursor.execute(queries[-1]).fetchone()[0]\n')
            case = 'closure-future-owner-' + label
            with self.subTest(future_owner=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / (case + '.py')
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure.*incomplete'):
                    list(detector.find([path]))

    def test_recursive_closure_boundaries_remain_explicit(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        for name, body in (
                ('recursive-return', '    queries = []\n    def add(value, again):\n'
                 '        if again:\n            return add(value, False)\n'
                 '        queries.append(value)\n        return value\n'),
                ('recursive-nonlocal', '    queries = []\n    flag = True\n    def add(value, again):\n'
                 '        nonlocal flag\n        flag = False\n'
                 '        if again:\n            add(value, False)\n        else:\n            queries.append(value)\n'),
                ('recursive-root-alias', '    queries = []\n    alias = queries\n    def add(value, again):\n'
                 '        if again:\n            add(value, False)\n        else:\n            queries.append(value)\n')):
            source = program(body + f'    add({unsafe}, True)\n'
                             '    return cursor.execute(queries[-1]).fetchone()[0]\n')
            with self.subTest(case=name):
                self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], 2)
                path = self.artifacts / f'{name}.py'
                path.write_text(source, encoding='utf-8')
                if name in {'recursive-return', 'recursive-nonlocal'}:
                    line = next(index for index, text in enumerate(source.splitlines(), 1)
                                if 'return cursor.execute' in text)
                    self.inspect(name, source, ((CRITICAL, line),))
                else:
                    with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure.*incomplete'):
                        list(detector.find([path]))
        source = ('def execute_hidden(cursor, query):\n    return cursor.execute(query).fetchone()[0]\n'
                  + program('    queries = []\n    def add(value, again):\n'
                            '        if again:\n            add(value, False)\n'
                            '        else:\n            queries.append(execute_hidden(cursor, value))\n'
                            + f'    add({unsafe}, True)\n    return queries[-1]\n'))
        self.assertEqual(sqlite_witness(self.artifacts, 'recursive-opaque-call', source)['rows'], 2)
        path = self.artifacts / 'recursive-opaque-call.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'consumer call effects.*incomplete'):
            list(detector.find([path]))

    def test_mutating_an_earlier_list_argument_is_not_a_clean_snapshot(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        proxy = ('class DeferredCursor:\n    def __init__(self, cursor):\n        self.cursor = cursor\n'
                 '    def execute(self, queries, params=None):\n        return self.cursor.execute(queries[-1])\n')
        for name, declaration, mutation in (
                ('direct', '', f'queries.append({unsafe})'),
                ('closure', '    def add(value):\n        queries.append(value)\n', f'add({unsafe})'),
                ('recursive', '    def add(value, again):\n        if again:\n'
                 '            add(value, False)\n        else:\n            queries.append(value)\n', f'add({unsafe}, True)')):
            for choice, expression in (('name', 'queries'), ('conditional', 'queries if user else queries'),
                                       ('boolean', 'queries or queries')):
                source = proxy + program('    queries = ["SELECT count(*) FROM users WHERE name = \'alice\'"]\n'
                                         + declaration + '    deferred = DeferredCursor(cursor)\n'
                                         + f'    return deferred.execute({expression}, params={mutation}).fetchone()[0]\n')
                label = f'argument-list-{name}-{choice}'
                with self.subTest(case=name, choice=choice):
                    self.assertEqual(sqlite_witness(self.artifacts, label, source)['rows'], 2)
                    path = self.artifacts / f'{label}.py'
                    path.write_text(source, encoding='utf-8')
                    with self.assertRaisesRegex(detector.SQLFlowLimit, 'mutation during argument evaluation.*incomplete'):
                        list(detector.find([path]))

    def test_list_insertions_and_mutator_capabilities_are_not_clean(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for method in ('insert', '__setitem__'):
            for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program(f'    queries = [{safe}]\n'
                                 f'    queries.{method}(0, {query})\n'
                                 '    return cursor.execute(queries[0]).fetchone()[0]\n')
                name = f'list-{method}-{label}'
                with self.subTest(method=method, label=label):
                    self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], rows)
                    self.inspect(name, source, ((CRITICAL, 4),) if rows == 2 else ())
        mutations = (
            ('bound-append', '    write = queries.append\n', f'    write({unsafe})\n'),
            ('bound-extend', '    write = queries.extend\n', f'    write([{unsafe}])\n'),
            ('reflected-append', '    write = getattr(queries, "append")\n', f'    write({unsafe})\n'),
            ('unbound-append', '', f'    list.append(queries, {unsafe})\n'),
            ('unbound-extend', '', f'    list.extend(queries, [{unsafe}])\n'),
            ('aliased-unbound', '    write = list.append\n', f'    write(queries, {unsafe})\n'),
        )
        for name, declaration, mutation in mutations:
            source = program('    queries = []\n' + declaration + mutation +
                             '    return cursor.execute(queries[0]).fetchone()[0]\n')
            with self.subTest(capability=name):
                self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], 2)
                path = self.artifacts / f'list-capability-{name}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'list mutation.*incomplete'):
                    list(detector.find([path]))
        source = program(f'    queries = [{safe}]\n    first = queries[0]\n'
                         f'    queries.insert(0, {unsafe})\n'
                         '    return cursor.execute(first).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'insert-keeps-captured-value', source)['rows'], 1)
        self.inspect('insert-keeps-captured-value', source, ())
        source = program(f'    queries = [{safe}]\n    copy_queries = queries.copy\n'
                         '    return cursor.execute(copy_queries()[0]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'copy-is-not-a-mutator', source)['rows'], 1)
        self.inspect('copy-is-not-a-mutator', source, ())

    def test_indexed_stores_preserve_sql_and_target_evaluation_order(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        writes = (
            ('assignment', '    queries[0] = {query}\n'),
            ('annotation', '    queries[0]: str = {query}\n'),
            ('augmentation', '    queries[0] += {query}\n'),
            ('slice', '    queries[:] = [{query}]\n'),
            ('negative-index', '    queries[-1] = {query}\n'),
            ('bounded-slice', '    queries[0:1] = [{query}]\n'),
            ('for-target', '    for queries[0] in [{query}]:\n        pass\n'),
            ('comprehension-target', '    unused = [None for queries[0] in [{query}]]\n'),
            ('ordered-unpacking', '    index, queries[index] = 0, {query}\n'),
            ('enumerated-index', '    for index, query in enumerate([{query}]):\n        queries[index] = query\n'),
            ('closure-item', '    def store(value):\n        queries[0] = value\n    store({query})\n'),
            ('closure-slice', '    def store(value):\n        queries[:] = [value]\n    store({query})\n'),
            ('closure-target', '    def store(value):\n        for queries[0] in [value]:\n            pass\n    store({query})\n'),
        )
        for name, write in writes:
            for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program('    queries = [""]\n' + write.format(query=query)
                                 + '    return cursor.execute(queries[0]).fetchone()[0]\n')
                case = f'indexed-{name}-{label}'
                line = next(index for index, text in enumerate(source.splitlines(), 1)
                            if 'return cursor.execute' in text)
                with self.subTest(write=name, value=label):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, line),) if rows == 2 else ())
        for name, body in (
                ('generator-item', '    queries = [[]]\n'
                 f'    queries[0] = ({unsafe} for item in [1])\n'
                 '    queries = list(queries[0])\n'),
                ('generator-augmented-item', '    queries = [[]]\n'
                 f'    queries[0] += ({unsafe} for item in [1])\n'
                 '    queries = queries[0]\n'),
                ('escaped-item', f'    queries = [{safe}]\n    alias = queries\n'
                 f'    queries[0] = {unsafe}\n    queries = alias\n'),
                ('rebound-augmented-receiver', '    queries = [""]\n'
                 f'    queries[0] += ((alias := queries), (queries := ["ignored"]), {unsafe})[-1]\n'
                 '    queries = alias\n'),
                ('closure-list-as-index', '    class Holder:\n'
                 '        def __setitem__(self, key, value):\n            self.saved = key\n'
                 f'    queries = [{safe}]\n    holder = Holder()\n'
                 '    def capture():\n        holder[queries] = None\n'
                 f'    capture()\n    queries.append({unsafe})\n    queries = holder.saved[-1:]\n')):
            source = program(body + '    return cursor.execute(queries[0]).fetchone()[0]\n')
            with self.subTest(refusal=name):
                self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], 2)
                path = self.artifacts / f'indexed-refusal-{name}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'list mutation.*incomplete'):
                    list(detector.find([path]))
        source = program(f'    queries = [{safe}]\n    first = queries[0]\n'
                         f'    queries[0] = {unsafe}\n'
                         '    return cursor.execute(first).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'item-keeps-scalar-snapshot', source)['rows'], 1)
        self.inspect('item-keeps-scalar-snapshot', source, ())
        source = program(f'    queries = [{safe}, {safe}]\n'
                         '    counts = [cursor.execute(query).fetchone()[0] for query in queries\n'
                         f'              for queries[1] in [{unsafe}]]\n'
                         '    return max(counts)\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'comprehension-mutates-future-item', source)['rows'], 2)
        path = self.artifacts / 'comprehension-mutates-future-item.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'mutation during list iteration.*incomplete'):
            list(detector.find([path]))
        source = program(f'    for index, unused in enumerate([{unsafe}]):\n'
                         '        return cursor.execute(f"SELECT {index + 1}").fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'enumerate-index-is-not-the-element', source)['rows'], 1)
        self.inspect('enumerate-index-is-not-the-element', source, ())
        prefix = 'class Index:\n    def __index__(self):\n        return 0\n'
        body = f'    queries = [{safe}]\n    queries[Index()] = {safe}\n'
        source = prefix + program(body + '    return cursor.execute(queries[0]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'opaque-index-no-sql', source)['rows'], 1)
        self.inspect('opaque-index-no-sql', source, ())
        source = prefix + program(body + f'    queries.append({unsafe})\n'
                                  '    return cursor.execute(queries[-1]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'opaque-index-revokes-ownership', source)['rows'], 2)
        path = self.artifacts / 'opaque-index-revokes-ownership.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'list mutation.*incomplete'):
            list(detector.find([path]))

        for label, mutation in (
                ('attribute', 'builtins.enumerate = replacement'),
                ('setattr', 'setattr(builtins, "enumerate", replacement)'),
                ('namespace', 'builtins.__dict__["enumerate"] = replacement')):
            source = 'import builtins\n' + program(
                '    original = builtins.enumerate\n'
                '    replacement = lambda values: [(user, None)]\n'
                '    try:\n'
                f'        {mutation}\n'
                '        for index, unused in enumerate([1]):\n'
                '            return cursor.execute(f"SELECT count(*) FROM users WHERE name = \'{index}\'").fetchone()[0]\n'
                '    finally:\n        builtins.enumerate = original\n')
            line = next(index for index, text in enumerate(source.splitlines(), 1)
                        if 'return cursor.execute' in text)
            with self.subTest(enumerate_override=label):
                name = f'enumerate-monkeypatch-{label}'
                self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], 2)
                self.inspect(name, source, ((CRITICAL, line),))

    def test_numeric_and_repeated_sequence_shapes_preserve_sql(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for label, write in (
                ('difference-index', '    queries[3 - 3] = {query}\n'),
                ('augmented-index', '    index = 1\n    index -= 1\n    queries[index] = {query}\n'),
                ('length-index', '    queries[len([0]) - 1] = {query}\n'),
                ('length-slice', '    queries[:len([0])] = [{query}]\n'),
                ('enumerate-start', '    for index, unused in enumerate([0], 1):\n'
                 '        queries[index - 1] = {query}\n'),
                ('enumerate-keyword-start', '    for index, unused in enumerate([0], start=1):\n'
                 '        queries[index - 1] = {query}\n'),
                ('enumerate-index-protocol', '    class Start:\n'
                 '        def __index__(self):\n            return 1\n'
                 '    for index, unused in enumerate([0], Start()):\n'
                 '        queries[index - 1] = {query}\n'),
                ('fresh-repeated-owner', f'    queries = [{safe}] * len([0])\n'
                 '    queries[0] = {query}\n'),
                ('fresh-reflected-owner', f'    queries = len([0]) * [{safe}]\n'
                 '    queries[0] = {query}\n'),
                ('repeat-list', '    queries[:] = [{query}] * (3 - 2)\n'),
                ('repeat-list-reflected', '    queries[:] = (3 - 2) * [{query}]\n'),
                ('repeat-tuple', '    queries[:] = ({query},) * (3 - 2)\n'),
                ('repeat-string', '    queries[:] = "".join([{query}]) * (3 - 2)\n')):
            for name, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program(f'    queries = [{safe}]\n' + write.format(query=query)
                                 + '    return cursor.execute("".join(queries)).fetchone()[0]\n')
                case = f'numeric-sequence-{label}-{name}'
                line = next(index for index, text in enumerate(source.splitlines(), 1)
                            if 'return cursor.execute' in text)
                with self.subTest(shape=label, value=name):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, line),) if rows == 2 else ())

        for label, prefix, write in (
                ('custom-index', 'class Index:\n    def __sub__(self, other):\n        return 0\n',
                 '    queries[Index() - 0] = {query}\n'),
                ('custom-count', 'class Count:\n    def __index__(self):\n        return 1\n',
                 '    queries[:] = [{query}] * Count()\n'),
                ('shadowed-length', '', '    len = lambda values: values[0]\n'
                 '    queries[:] = len([[{query}]])\n')):
            source = prefix + program(f'    queries = [{safe}]\n' + write.format(query=unsafe)
                                      + '    return cursor.execute("".join(queries)).fetchone()[0]\n')
            with self.subTest(refusal=label):
                case = f'numeric-sequence-refusal-{label}'
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / f'{case}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'list mutation.*incomplete'):
                    list(detector.find([path]))

        for label, mutation in (
                ('attribute', 'builtins.len = replacement'),
                ('setattr', 'setattr(builtins, "len", replacement)'),
                ('namespace', 'builtins.__dict__["len"] = replacement')):
            source = 'import builtins\n' + program(
                '    original = builtins.len\n    replacement = lambda values: values[0]\n'
                + f'    queries = [{safe}]\n    try:\n        {mutation}\n'
                + f'        queries[:] = len([[{unsafe}]])\n'
                + '        return cursor.execute("".join(queries)).fetchone()[0]\n'
                + '    finally:\n        builtins.len = original\n')
            with self.subTest(length_override=label):
                case = f'numeric-sequence-length-override-{label}'
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / f'{case}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'list mutation.*incomplete'):
                    list(detector.find([path]))

        source = program('    queries = ["SELECT 1"]\n'
                         + f'    index = len([(seen := cursor.execute({unsafe}).fetchone()[0])]) - 1\n'
                         + '    queries[index] = "SELECT 1"\n    return seen\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'numeric-length-eager-sink', source)['rows'], 2)
        self.inspect('numeric-length-eager-sink', source, ((CRITICAL, 3),))

        for label, mutation in (
                ('attribute', 'builtins.range = replacement'),
                ('setattr', 'setattr(builtins, "range", replacement)'),
                ('namespace', 'builtins.__dict__["range"] = replacement')):
            source = 'import builtins\n' + program(
                '    class Index:\n        def __sub__(self, other):\n            return 0\n'
                '    original = builtins.range\n    replacement = lambda count: [Index()]\n'
                + f'    queries = [{safe}]\n    try:\n        {mutation}\n'
                + '        for index in range(1):\n'
                + f'            queries[index - 0] = {unsafe}\n'
                + '        return cursor.execute(queries[0]).fetchone()[0]\n'
                + '    finally:\n        builtins.range = original\n')
            with self.subTest(range_override=label):
                case = f'numeric-sequence-range-override-{label}'
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / f'{case}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'opaque index.*incomplete'):
                    list(detector.find([path]))

    def test_builtin_sequence_reads_retain_shapes_and_sql_effects(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for label, setup, write, read in (
                ('tuple-index', '    indices = (0,)\n', 'queries[indices[0]] = {query}', 'queries[0]'),
                ('boolean-index', '    indices = (False,)\n', 'queries[indices[0]] = {query}', 'queries[0]'),
                ('private-list-index', '    indices = [0]\n', 'queries[indices[0]] = {query}', 'queries[0]'),
                ('tuple-slice', '    indices = (0, 1)\n', 'queries[indices[:1][0]] = {query}', 'queries[0]'),
                ('fresh-list-slice', '    copied = queries[:]\n', 'copied[0] = {query}', 'copied[0]'),
                ('private-list-slice', '    values = [{query}]\n', 'queries[:] = values[:]', 'queries[0]'),
                ('string-index', '', 'queries[:] = "".join([{query}])[0]', '"".join(queries) + "".join([{query}])[1:]'),
                ('string-slice', '', 'queries[:] = "".join([{query}])[:]', '"".join(queries)')):
            for value, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program('    queries = [""]\n' + setup.format(query=query)
                                 + '    ' + write.format(query=query) + '\n'
                                 + '    return cursor.execute(' + read.format(query=query) + ').fetchone()[0]\n')
                line = next(index for index, text in enumerate(source.splitlines(), 1)
                            if 'return cursor.execute' in text)
                case = f'sequence-read-{label}-{value}'
                with self.subTest(sequence=label, value=value):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, line),) if rows == 2 else ())
        prefix = 'class Index:\n    def __index__(self):\n        return 0\n'
        for label, setup, index in (
                ('aliased-elements', '    indices = [0]\n    alias = indices\n    alias[0] = Index()\n', 'indices[0]'),
                ('custom-index', '    indices = (0,)\n', 'indices[Index()]'),
                ('custom-getitem', '    class Indices:\n        def __getitem__(self, key):\n            return Index()\n'
                 '    indices = Indices()\n', 'indices[0]')):
            source = prefix + program('    queries = [""]\n' + setup
                                      + f'    queries[{index}] = {unsafe}\n'
                                      + '    return cursor.execute(queries[0]).fetchone()[0]\n')
            case = f'sequence-read-refusal-{label}'
            with self.subTest(refusal=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / (case + '.py')
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'opaque index.*incomplete'):
                    list(detector.find([path]))

        source = program('    indices = (0,)\n    queries = ["SELECT 1"]\n'
                         + f'    index = indices[len([cursor.execute({unsafe}).fetchone()[0]]) - 1]\n'
                         + '    queries[index] = "SELECT 1"\n    return 2\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'sequence-read-eager-sink', source)['rows'], 2)
        self.inspect('sequence-read-eager-sink', source, ((CRITICAL, 4),))

        source = program(f'    queries = [{safe}]\n    copied = queries[:]\n'
                         + f'    copied[0] = {unsafe}\n'
                         + '    return cursor.execute(queries[0]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'sequence-slice-distinct-storage', source)['rows'], 1)
        self.inspect('sequence-slice-distinct-storage', source, ())

        for label, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
            source = program(f'    queries = [{safe}]\n    index = [0][0]\n'
                             + f'    queries[index] = {query}\n'
                             + '    return cursor.execute(queries[0]).fetchone()[0]\n')
            case = 'sequence-anonymous-index-' + label
            with self.subTest(anonymous_index=label):
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                self.inspect(case, source, ((CRITICAL, 5),) if rows == 2 else ())

        source = program('    containers = [[""]]\n    captured = containers[0]\n'
                         + f'    captured[0] = {unsafe}\n'
                         + '    return cursor.execute(containers[0][0]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'sequence-item-retains-alias', source)['rows'], 2)
        path = self.artifacts / 'sequence-item-retains-alias.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'list mutation at an aliased target.*incomplete'):
            list(detector.find([path]))

    def test_frame_namespaces_invalidate_builtin_index_shapes(self):
        for label, imports, expression in (
                ('sys-builtins', 'import sys\n', 'sys._getframe().f_builtins'),
                ('inspect-builtins', 'import inspect\n', 'inspect.currentframe().f_builtins'),
                ('sys-globals', 'import sys\n', 'sys._getframe().f_globals'),
                ('aliased-frame', 'from sys import _getframe as capture\n',
                 'getattr(capture(), "f_builtins")'),
                ('computed-frame', 'import sys\n',
                 'getattr(getattr(sys, "_get" + "frame")(), "f_" + "builtins")'),
                ('aliased-lookup', 'import sys\nlookup = getattr\n',
                 'lookup(lookup(sys, "_getframe")(), "f_builtins")'),
                ('transitive-lookup', 'import sys\nlookup = getattr\nread = lookup\n',
                 'read(read(sys, "_getframe")(), "f_builtins")'),
                ('expanded-lookup', 'import sys\n',
                 'getattr(*(getattr(*(sys, "_getframe"))(), "f_builtins"))'),
                ('packed-lookup', 'import sys\nlookups = (getattr,)\n',
                 'lookups[0](lookups[0](sys, "_getframe")(), "f_builtins")'),
                ('partial-lookup', 'import sys\nfrom functools import partial\nlookup = partial(getattr)\n',
                 'lookup(lookup(sys, "_getframe")(), "f_builtins")'),
                ('conditional-lookup', 'import sys\nif False:\n    getattr = None\n',
                 'getattr(getattr(sys, "_get" + "frame")(), "f_" + "builtins")'),
                ('object-getattribute', 'import sys\n',
                 'object.__getattribute__(object.__getattribute__(sys, "_getframe")(), "f_builtins")'),
                ('attribute-factory', 'import sys\nfrom operator import attrgetter as read\n',
                 'read("f_builtins")(read("_getframe")(sys)())'),
                ('method-factory', 'import sys\nfrom operator import methodcaller as read\n',
                 'read("__getattribute__", "f_builtins")(read("_getframe")(sys))')):
            source = imports + program(f'    namespace = {expression}\n'
                '    original = namespace.get("enumerate", enumerate)\n'
                '    try:\n        namespace["enumerate"] = lambda values: [(user, None)]\n'
                '        for index, unused in enumerate([1]):\n'
                '            return cursor.execute(f"SELECT count(*) FROM users WHERE name = \'{index}\'").fetchone()[0]\n'
                '    finally:\n        namespace["enumerate"] = original\n')
            line = next(index for index, text in enumerate(source.splitlines(), 1)
                        if 'return cursor.execute' in text)
            with self.subTest(frame=label):
                case = f'frame-enumerate-{label}'
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                self.inspect(case, source, ((CRITICAL, line),))

        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for label, prefix in (
                ('literal-lookup', '    import sys\n    getattr(sys, "version")\n'),
                ('shadowed-lookup', '    def getattr(value, name):\n        return "unused"\n'
                 '    getattr(None, user)\n'),
                ('shadowed-alias', '    def getattr(value, name):\n        return "unused"\n'
                 '    lookup = getattr\n    lookup(None, user)\n')):
            for name, query, rows in (('safe', safe, 1), ('unsafe', unsafe, 2)):
                source = program(prefix + f'    queries = [{safe}]\n'
                                 '    for index in range(1):\n'
                                 + f'        queries[index] = {query}\n'
                                 + '    return cursor.execute("".join(queries)).fetchone()[0]\n')
                case = f'frame-lookup-control-{label}-{name}'
                line = next(index for index, text in enumerate(source.splitlines(), 1)
                            if 'return cursor.execute' in text)
                with self.subTest(control=label, value=name):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, line),) if rows == 2 else ())

    def test_string_return_shapes_preserve_sql_and_effects(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        safe = '"SELECT count(*) FROM users WHERE name = \'alice\'"'
        for label, helper, expression in (
                ('join', '', '"".join([{query}])'),
                ('generator-join', '', '"".join(query for query in [{query}])'),
                ('local', '    def render(value):\n        return "".join([value])\n', 'render({query})'),
                ('recursive', '    def render(value, depth=0):\n'
                 '        if depth:\n            value = render(value, depth - 1)\n'
                 '        return "".join([value])\n', 'render({query}, 1)'),
                ('formatted-return', '    def render(value):\n        return "".join([f"{value}"])\n', 'render({query})')):
            for name, query, rows in (('unsafe', unsafe, 2), ('safe', safe, 1)):
                source = program(helper + '    queries = []\n'
                                 + f'    queries[:] = {expression.format(query=query)}\n'
                                 + '    return cursor.execute("".join(queries)).fetchone()[0]\n')
                case = f'string-slice-{label}-{name}'
                line = next(index for index, text in enumerate(source.splitlines(), 1)
                            if 'return cursor.execute' in text)
                with self.subTest(shape=label, value=name):
                    self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], rows)
                    self.inspect(case, source, ((CRITICAL, line),) if rows == 2 else ())

        for label, helper, expression in (
                ('mixed-return', '    def render(value):\n'
                 '        if value:\n            return [value]\n        return ""\n', 'render({query})'),
                ('decorated', '    def replace(function):\n        return lambda value: [value]\n'
                 '    @replace\n    def render(value):\n        return ""\n', 'render({query})'),
                ('generator', '    def render(value):\n        yield value\n        return ""\n', 'render({query})'),
                ('yield-in-return', '    def render(value):\n        return f"{(yield value)}"\n', 'render({query})'),
                ('formatted-subclass', '    class Text(str):\n'
                 '        def __iter__(self):\n            yield str(self)\n'
                 '    class Value:\n        def __init__(self, text):\n            self.text = text\n'
                 '        def __format__(self, spec):\n            return Text(self.text)\n'
                 '    def render(value):\n        return f"{value}"\n', 'render(Value({query}))'),
                ('escaped-code', '    def render(value):\n        return ""\n'
                 '    def replacement(value):\n        return [value]\n'
                 '    alias = render\n    alias.__code__ = replacement.__code__\n', 'render({query})')):
            source = program(helper + f'    queries = [{safe}]\n'
                             + f'    queries[:] = {expression.format(query=unsafe)}\n'
                             + '    return cursor.execute("".join(queries)).fetchone()[0]\n')
            with self.subTest(refusal=label):
                case = f'string-slice-refusal-{label}'
                self.assertEqual(sqlite_witness(self.artifacts, case, source)['rows'], 2)
                path = self.artifacts / f'{case}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'opaque slice iterable.*incomplete'):
                    list(detector.find([path]))

        source = 'def render(value):\n    return ""\n' + program(
            '    import sys\n    sys.modules[__name__].render = lambda value: [value]\n'
            + f'    queries = [{safe}]\n    queries[:] = render({unsafe})\n'
            + '    return cursor.execute("".join(queries)).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'string-module-replacement', source)['rows'], 2)
        path = self.artifacts / 'string-module-replacement.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'opaque slice iterable.*incomplete'):
            list(detector.find([path]))

    def test_real_sqlite_closure_mutations_are_not_clean(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        source = program('    queries = []\n    def add(value):\n        queries.append(value)\n'
                         f'    add({unsafe})\n'
                         '    return cursor.execute(queries[0]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'private-closure-append', source)['rows'], 2)
        self.inspect('private-closure-append', source, ((CRITICAL, 6),))
        for name, body in (
                ('late-list', '    def add(value):\n        queries.append(value)\n    queries = []\n'),
                ('escaped-callable', '    queries = []\n    def add(value):\n        queries.append(value)\n    held = add\n'),
                ('escaped-root', '    queries = []\n    alias = queries\n    def add(value):\n        queries.append(value)\n'),
                ('default-argument', '    queries = []\n    def add(value, unused=user):\n        queries.append(value)\n')):
            source = program(body + f'    add({unsafe})\n'
                             '    return cursor.execute(queries[0]).fetchone()[0]\n')
            with self.subTest(case=name):
                self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], 2)
                path = self.artifacts / f'closure-refusal-{name}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure list ownership.*incomplete'):
                    list(detector.find([path]))
        source = program('    queries = []\n    def add(value):\n        queries.append(value)\n'
                         '    held = add\n' + f'    held({unsafe})\n'
                         '    return cursor.execute(queries[0]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'aliased-closure-call', source)['rows'], 2)
        path = self.artifacts / 'aliased-closure-call.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure list ownership.*incomplete'):
            list(detector.find([path]))
        source = program('    queries = ["SELECT count(*) FROM users WHERE name = \'alice\'"]\n'
                         '    def add(value):\n        queries.append(value)\n'
                         '    first = True\n    for query in queries:\n'
                         '        if first:\n' + f'            add({unsafe})\n'
                         '            first = False\n            continue\n'
                         '        return cursor.execute(query).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'closure-during-iteration', source)['rows'], 2)
        path = self.artifacts / 'closure-during-iteration.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure mutation during list iteration.*incomplete'):
            list(detector.find([path]))
        source = program('    queries = [' + unsafe + ']\n'
                         '    def read():\n        return queries[0]\n'
                         '    return cursor.execute(read()).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'private-closure-return', source)['rows'], 2)
        self.inspect('private-closure-return', source, ((CRITICAL, 5),))
        for name, abrupt in (('break', 'break'), ('return', 'return "SELECT count(*) FROM users WHERE name = \'alice\'"')):
            source = program('    queries = []\n    def add():\n        for item in [1]:\n'
                             '            try:\n' + f'                return {unsafe}\n'
                             '            finally:\n' + f'                {abrupt}\n'
                             '        queries.append("SELECT 1")\n'
                             '        return "SELECT count(*) FROM users WHERE name = \'alice\'"\n'
                             '    return cursor.execute(add()).fetchone()[0]\n')
            with self.subTest(finally_exit=name):
                self.assertEqual(sqlite_witness(self.artifacts, f'closure-finally-{name}', source)['rows'], 1)
                self.inspect(f'closure-finally-{name}', source, ())
        source = program('    queries = []\n    def add(value):\n        queries.append(value)\n'
                         '        return (value for item in [1])\n'
                         f'    pending = add({unsafe})\n'
                         '    return cursor.execute(next(pending)).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'closure-generator-return', source)['rows'], 2)
        path = self.artifacts / 'closure-generator-return.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure generator escape.*incomplete'):
            list(detector.find([path]))
        for name, expression in (
                ('saved-predicate', '    pending = (query == "SELECT 1" for query in queries)\n    any(pending)\n'),
                ('predicate-callback', '    any(hold(queries) for query in queries)\n'),
                ('predicate-root-yield', '    any(queries for query in [1])\n'),
                ('predicate-exception-frame', '    try:\n        any(query == "SELECT 1" for query in queries)\n    except Exception:\n        pass\n')):
            source = program('    queries = ["SELECT 1"]\n'
                             '    def add(value):\n        queries.append(value)\n'
                             + expression + f'    add({unsafe})\n' + '    cursor.execute(queries[-1])\n')
            with self.subTest(boundary=name):
                path = self.artifacts / f'closure-predicate-refusal-{name}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure list ownership.*incomplete'):
                    list(detector.find([path]))
        source = program('    saved = []\n    queries = [] if not user else saved\n'
                         f'    queries.append({unsafe})\n'
                         '    return cursor.execute(saved[0]).fetchone()[0]\n')
        self.assertEqual(sqlite_witness(self.artifacts, 'conditional-root-alias', source)['rows'], 2)
        path = self.artifacts / 'conditional-root-alias.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'list mutation.*incomplete'):
            list(detector.find([path]))
        source = program('    queries = ["SELECT count(*) FROM users WHERE name = \'alice\'"]\n'
                         '    def add():\n' + f'        queries.append({unsafe})\n'
                         '    sum(add() or 0 for query in queries)\n'
                         '    cursor.execute(queries[-1])\n')
        path = self.artifacts / 'closure-during-reducer.py'
        path.write_text(source, encoding='utf-8')
        with self.assertRaisesRegex(detector.SQLFlowLimit, 'closure mutation during list iteration.*incomplete'):
            list(detector.find([path]))

    def test_closure_lexical_and_lazy_boundaries_are_not_clean(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        cases = (
            ('comprehension-frame', '    queries = []\n    query = "SELECT 1"\n'
             '    def add():\n        queries.append(query)\n' + f'    query = {unsafe}\n'
             '    unused = [add() for query in ["SELECT 1"]]\n'
             '    return cursor.execute(queries[0]).fetchone()[0]\n', 'closure lexical frame'),
            ('lazy-helper-effect', '    queries = []\n    def add():\n'
             + f'        queries.append({unsafe})\n'
             '    def consume(values):\n        for value in values:\n            pass\n'
             '    pending = (add() for item in [1])\n    consume(pending)\n'
             '    return cursor.execute(queries[0]).fetchone()[0]\n', 'closure list ownership'),
            ('lazy-raw-list-effect', '    queries = []\n'
             '    def consume(values):\n        for value in values:\n            pass\n'
             '    consume(queries.append(user) for item in [1])\n'
             '    return cursor.execute(f"SELECT count(*) FROM users WHERE name = \'{queries[0]}\'").fetchone()[0]\n',
             'list mutation aliasing'),
            ('match-consumer-shadow', f'    query = {unsafe}\n'
             '    def ignore(values):\n        pass\n'
             '    match ignore:\n        case list:\n'
             '            pending = ((query := "SELECT 1") for item in [1])\n'
             '            list(pending)\n'
             '    return cursor.execute(query).fetchone()[0]\n', 'unknown generator consumer'),
            ('except-consumer-shadow', f'    query = {unsafe}\n'
             '    class Ignore(Exception):\n        def __call__(self, values):\n            pass\n'
             '    try:\n        raise Ignore()\n    except Ignore as list:\n'
             '        pending = ((query := "SELECT 1") for item in [1])\n'
             '        list(pending)\n'
             '    return cursor.execute(query).fetchone()[0]\n', 'unknown generator consumer'),
            *((f'{consumer}-helper-effect', '    queries = []\n    def add():\n'
               + f'        queries.append({unsafe})\n'
               + f'    {consumer}(add() for item in [1])\n'
               '    return cursor.execute(queries[0]).fetchone()[0]\n', 'closure list ownership')
              for consumer in ('any', 'all')),
        )
        for name, body, reason in cases:
            with self.subTest(case=name):
                source = program(body)
                self.assertEqual(sqlite_witness(self.artifacts, name, source)['rows'], 2)
                path = self.artifacts / f'{name}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, reason + '.*incomplete'):
                    list(detector.find([path]))
        self.inspect('opaque-generator-no-captured-list', program(
            '    def nothing(value):\n        return None\n'
            '    consume(nothing(item) for item in [1])\n'), ())
        self.inspect('opaque-generator-numeric-list-effects', program(
            '    values = []\n    consume(values.append(index) for index in range(3))\n'), ())
        for consumer in ('any', 'all'):
            self.inspect(f'{consumer}-sql-values-are-only-predicates', program(
                f'    {consumer}({unsafe} for item in [1])\n'), ())
            self.inspect(f'{consumer}-private-nested-cursors', program(
                f'    {consumer}(any(index == other for other in [1]) for index in [1])\n'), ())
        for consumer in ('any', 'all', 'next'):
            source = program('    pending = ("SELECT 1" for item in [1])\n'
                             f'    {consumer}(list(pending) for item in [1])\n'
                             '    cursor.execute(next(pending, "SELECT 1"))\n')
            with self.subTest(consumer=consumer):
                path = self.artifacts / f'{consumer}-captured-cursor-effect.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'partial generator effects.*incomplete'):
                    list(detector.find([path]))

    def test_real_sqlite_list_iteration_mutations_are_not_clean(self):
        unsafe = 'f"SELECT count(*) FROM users WHERE name = \'{user}\'"'
        for index, iterable in enumerate(('queries', 'iter(queries)')):
            source = program('    queries = ["SELECT count(*) FROM users WHERE name = \'alice\'"]\n'
                             '    first = True\n' + f'    for query in {iterable}:\n'
                             '        if first:\n' + f'            queries.append({unsafe})\n'
                             '            first = False\n            continue\n'
                             '        return cursor.execute(query).fetchone()[0]\n')
            with self.subTest(iterable=iterable):
                self.assertEqual(sqlite_witness(self.artifacts, f'list-iteration-{index}', source)['rows'], 2)
                path = self.artifacts / f'list-iteration-{index}.py'
                path.write_text(source, encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'mutation during list iteration.*incomplete'):
                    list(detector.find([path]))

    def test_exhausted_generator_reallocation_does_not_resurrect_aliases(self):
        cases = (
            ('stream-exhaustion', '    pending = (f"SELECT {user}" for item in [1])\n    for query in pending:\n        pass\n    qs.extra(where=list(pending))\n', ()),
            ('stream-already-exhausted', '    pending = (f"SELECT {user}" for item in [1])\n    list(pending)\n    for query in pending:\n        cursor.execute(f"SELECT {user}")\n', ()),
            ('reallocate-after-drain', '    for item in rows:\n        pending = (f"SELECT {user}" for unused in [1])\n        list(pending)\n', ()),
            ('reallocate-after-stream', '    for item in rows:\n        pending = (f"SELECT {user}" for unused in [1])\n        for query in pending:\n            cursor.execute(query)\n', ((CRITICAL, 5),)),
            ('reallocate-mixed-branch', '    for item in rows:\n        pending = ["SELECT 1"] if user else (f"SELECT {user}" for unused in [1])\n        for query in pending:\n            cursor.execute(query)\n', ((CRITICAL, 5),)),
        )
        for name, body, expected in cases:
            with self.subTest(case=name):
                self.inspect(name, program(body), expected)
        refusals = (
            '    for item in rows:\n        pending = (f"SELECT {user}" for unused in [1])\n        alias = pending\n        list(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    for item in rows:\n        pending = (f"SELECT {user}" for unused in [1])\n        for query in pending:\n            break\n    cursor.execute(next(pending, "SELECT 1"))\n',
            '    for item in rows:\n        pending = (f"SELECT {user}" for unused in [1])\n        wrapper = (query for query in pending)\n        list(pending)\n    cursor.execute(next(pending, "SELECT 1"))\n',
        )
        for index, body in enumerate(refusals):
            with self.subTest(refusal=index):
                path = self.artifacts / f'generator-reallocation-refusal-{index}.py'
                path.write_text(program(body), encoding='utf-8')
                with self.assertRaisesRegex(detector.SQLFlowLimit, 'generator.*incomplete'):
                    list(detector.find([path]))

    def test_real_sqlite_values(self):
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
            ('match-branch', f'    query = {fixed}\n    match user:\n        case _ if user:\n            query = {unsafe}\n        case _:\n            query = {fixed}\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 8),)),
            ('match-capture', '    match user:\n        case captured:\n            return cursor.execute(f"SELECT count(*) FROM users WHERE name = \'{captured}\'").fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('match-unpack', '    parts = ("SELECT count(*) FROM users WHERE name = \'", user, "\'")\n    match parts:\n        case (prefix, body, suffix):\n            return cursor.execute(prefix + body + suffix).fetchone()[0]\n', 2, ((CRITICAL, 5),)),
            ('match-nested-unpack', '    parts = (("SELECT count(*) FROM users WHERE name = \'", user), "\'")\n    match parts:\n        case ((prefix, body), suffix):\n            return cursor.execute(prefix + body + suffix).fetchone()[0]\n', 2, ((CRITICAL, 5),)),
            ('match-starred-unpack', '    parts = ("SELECT count(*) FROM users WHERE name = \'", user, "\'")\n    match parts:\n        case (prefix, *body, suffix):\n            return cursor.execute(prefix + body[0] + suffix).fetchone()[0]\n', 2, ((CRITICAL, 5),)),
            ('match-mapping-unpack', '    parts = {"prefix": "SELECT count(*) FROM users WHERE name = \'", "body": user, "suffix": "\'"}\n    match parts:\n        case {"prefix": prefix, "body": body, "suffix": suffix}:\n            return cursor.execute(prefix + body + suffix).fetchone()[0]\n', 2, ((CRITICAL, 5),)),
            ('match-clean-guard', f'    match user:\n        case captured if False:\n            return cursor.execute({unsafe}).fetchone()[0]\n        case _:\n            return cursor.execute({fixed}).fetchone()[0]\n', 1, ()),
            ('popped-query', f'    queries = [{unsafe}]\n    query = queries.pop()\n    queries.extend("SELECT 1" for unused in [1])\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 5),)),
            ('helper-list-owner', f'    def examine(values):\n        for value in reversed(values):\n            pass\n    queries = []\n    examine(queries)\n    queries.extend({unsafe} for item in [1])\n    return cursor.execute(queries[0]).fetchone()[0]\n', 2, ((CRITICAL, 8),)),
            ('left-capture', f'    query = {unsafe}\n    query += (query := " ")\n    return cursor.execute(query).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('dynamic-unpack', '    parts = ("SELECT count(*) FROM users WHERE name = \'", user, "\'")\n    prefix, body, suffix = parts\n    return cursor.execute(prefix + body + suffix).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('nested-unpack', '    parts = (("SELECT count(*) FROM users WHERE name = \'", user), "\'")\n    (prefix, body), suffix = parts\n    return cursor.execute(prefix + body + suffix).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('starred-unpack', '    parts = ("SELECT count(*) FROM users WHERE name = \'", user, "\'")\n    *[prefix, body, suffix], = parts\n    return cursor.execute(prefix + body + suffix).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('loop-unpack', '    rows = [("SELECT count(*) FROM users WHERE name = \'", user, "\'")]\n    for prefix, body, suffix in rows:\n        return cursor.execute(prefix + body + suffix).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
            ('comprehension-unpack', '    rows = [("SELECT count(*) FROM users WHERE name = \'", user, "\'")]\n    queries = [prefix + body + suffix for prefix, body, suffix in rows]\n    return cursor.execute(queries[0]).fetchone()[0]\n', 2, ((CRITICAL, 4),)),
        )
        for name, body, rows, expected in witnesses:
            with self.subTest(case=name):
                source = program(body)
                witness = sqlite_witness(self.artifacts, name, source, mode='keyword')
                actual = witness['rows']
                (self.artifacts / ('sqlite-' + name + '-execution.json')).write_text(json.dumps({
                    'sqlite_version': witness['sqlite_version'], 'expected_rows': rows,
                    'actual_rows': actual, 'python': witness['python'],
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
                witness = sqlite_witness(self.artifacts, name, source)
                actual = witness['rows']
                (self.artifacts / ('sqlite-comp-' + name + '-execution.json')).write_text(json.dumps({
                    'sqlite_version': witness['sqlite_version'], 'expected_rows': rows,
                    'actual_rows': actual, 'python': witness['python'],
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
                    'gen-alias-shares-exhaustion',
                    'next-projection-critical',
                    'next-default-critical',
                    'next-default-static',
                    'next-late-validation',
                    'gen-next-default-sql',
                    'gen-unpack-sql',
                    'gen-loop-sql',
                    'gen-extend-sql',
                    'gen-min-key-sql',
                    'gen-reallocate-sql',
                    'gen-receiver-rebind-sql',
                    'gen-mixed-unsafe-list',
                    'match-branch-sql',
                    'match-captured-sql',
                    'match-false-guard',
                    'list-pop-then-extend',
                    'list-conditional-item',
                    'list-insert-sql',
                    'list-setitem-sql',
                    'list-item-sql',
                    'list-ann-item-sql',
                    'list-aug-item-sql',
                    'list-slice-sql',
                    'list-for-target-sql',
                    'list-comp-target-sql',
                    'list-parallel-target-sql',
                    'string-slice-sql',
                    'generator-string-slice-sql',
                    'recursive-string-slice-sql',
                    'numeric-length-index-sql',
                    'numeric-repetition-slice-sql',
                    'numeric-repeated-owner-sql',
                    'numeric-repeated-owner-clean',
                    'numeric-enumerate-start-sql',
                    'frame-enumerate-sql',
                    'computed-frame-enumerate-sql',
                    'aliased-frame-enumerate-sql',
                    'transitive-frame-enumerate-sql',
                    'sequence-index-sql',
                    'sequence-slice-sql',
                    'sequence-slice-clean',
                    'sibling-closure-sql',
                    'sibling-closure-clean',
                    'recursive-return-sql',
                    'recursive-return-clean',
                    'closed-frame-sql',
                    'closed-frame-clean',
                    'record-frame-sql',
                    'record-frame-clean',
                    'list-parameter-sql',
                    'list-parameter-clean',
                    'tuple-bounds-sql',
                    'tuple-bounds-clean',
                    'regex-bounds-sql',
                    'regex-bounds-clean',
                    'recursive-tuple-shape-sql',
                    'recursive-tuple-shape-clean',
                    'sibling-cycle-sql',
                    'sibling-cycle-clean',
                    'sibling-cycle-return-sql',
                    'sibling-cycle-return-clean',
                    'match-sequence-sql',
                    'list-truth-test',
                    'list-read-only-helper',
                    'list-reversed-read',
                    'list-closure-append',
                    'list-immediate-predicate',
                    'closure-cell-copy-sql',
                    'closure-cell-copy-clean'}
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
                        try:
                            document = json.loads(result.stdout)
                        except json.JSONDecodeError as exc:
                            self.fail(f'CLI emitted invalid JSON: {command}; evidence: {folder}: {exc}')
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
        for name, body, flag, value, count, rule in cases:
            with self.subTest(case=name):
                source = ('def run(cursor, column, other, flag):\n' + textwrap.indent(body, '    ') +
                          '\n    return cursor.execute(f"SELECT count(*) FROM users WHERE name = \'{column}\'").fetchone()[0]\n')
                witness = sqlite_witness(self.artifacts, name, source, mode='validation', value=value, flag=flag)
                actual_count = witness['rows']
                path = self.artifacts / ('sqlite-' + name + '.py')
                path.write_text(source, encoding='utf-8')
                with patch.dict(os.environ, {detector.SANITIZER_ENV: self.VALIDATOR}):
                    findings = list(detector.find([path]))
                (self.artifacts / ('sqlite-' + name + '.json')).write_text(json.dumps({
                    'case': name, 'expected_rows': count, 'actual_rows': actual_count,
                    'expected_rule': rule, 'actual_rules': [item[0] for item in findings],
                    'sqlite_version': witness['sqlite_version'], 'python': witness['python'],
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
        for name, source, configuration, value, count, rule in cases:
            with self.subTest(case=name):
                witness = sqlite_witness(self.artifacts, name, source, mode='bindings', value=value)
                actual_count = witness['rows']
                path = self.artifacts / ('sqlite-' + name + '.py')
                path.write_text(source, encoding='utf-8')
                with patch.dict(os.environ, {detector.SANITIZER_ENV: configuration}):
                    actual = [(r, n) for r, _, n, _, _ in detector.find([path])]
                expected = [(rule, next(n for n, line in enumerate(source.splitlines(), 1)
                                        if 'cursor.execute(' in line))]
                path.with_suffix('.json').write_text(json.dumps({
                    'case': name, 'configuration': configuration, 'expected_rows': count,
                    'actual_rows': actual_count, 'expected_findings': expected, 'actual_findings': actual,
                    'sqlite_version': witness['sqlite_version'], 'python': witness['python'],
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
