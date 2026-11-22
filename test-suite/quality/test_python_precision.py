#!/usr/bin/env python3
"""Precision regressions for the Python layer (self-scan gate, bead D8).

`./ubs . --ci --fail-on-warning` on the ubs checkout itself reported 705
warnings and 0 criticals. Every one was a false positive, in six families;
each family is pinned here.

* ``py.numeric.division-heavy`` read ``pathlib`` joins as divisions
  (78 of 85 warnings were ``rules_dir / name``), and its text-prefix divisor
  test accepted an f-string denominator.
* ``py.debug.print`` counted every ``print(`` in the project, so a CLI whose
  job is writing to stdout failed its own gate (152 warnings across 76 files,
  75 of them command line entry points).
* ``py.collections.index-arithmetic`` matched the shape ``x[i + 1]`` with no
  notion of a bound, reporting 224 guarded neighbour lookups.
* ``py.io.open-missing-with`` counted the substring ``open(`` on raw lines, so
  docstrings and comments *about* open() counted as unmanaged file handles.
* ``py.comparison.is-literal`` / ``py.is-literal`` flagged ``x is True``,
  where the suggested ``==`` is not equivalent (``1 == True``).
* The pattern layer matched inside string literals, so a rule table that
  quotes ``$X == None`` or ``hashlib.md5($$$)`` reported itself.

Two real defects the fixed rules then found are pinned as well: the
``sg --version`` probe with no timeout, and the exponential-backtracking type
prefix in the Java/C# detectors.
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.io import iter_ndjson_lines, parse_ndjson_lines, read_ndjson, source_line  # noqa: E402
from ubs_core.py_detectors import division, index_arithmetic, io_open_checks, is_literal  # noqa: E402
from ubs_core.py_detectors import header_injection, json_loads, ldap_injection  # noqa: E402
from ubs_core.py_detectors import missing_returns  # noqa: E402
from ubs_core.py_detectors import sql_injection  # noqa: E402
from ubs_core.py_patterns.debug_typing import PATTERNS as DEBUG_PATTERNS  # noqa: E402
from ubs_core.py_patterns.flow import PATTERNS as FLOW_PATTERNS  # noqa: E402
from ubs_core.py_patterns.foundations import PATTERNS as FOUNDATION_PATTERNS  # noqa: E402
from ubs_core.py_patterns.io_files import PATTERNS as IO_PATTERNS  # noqa: E402
from ubs_core.py_patterns.quality import PATTERNS as QUALITY_PATTERNS  # noqa: E402
from ubs_core.py_patterns.security_rg import PATTERNS as SECURITY_PATTERNS  # noqa: E402
from ubs_core.py_scan import scan_patterns  # noqa: E402


def pattern(rule_id: str):
    for group in (DEBUG_PATTERNS, FLOW_PATTERNS, FOUNDATION_PATTERNS,
                  IO_PATTERNS, QUALITY_PATTERNS, SECURITY_PATTERNS):
        for entry in group:
            if entry.rule_id == rule_id:
                return entry
    raise AssertionError(f"unknown pattern {rule_id}")


class _Sink:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def write(self, line: str) -> None:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"Python precision sink record {len(self.records) + 1} is invalid JSON: "
                f"{line!r}; decoder error: {exc}"
            ) from exc
        self.records.append(record)


def run_patterns(rule_id: str, sources: dict[str, str]) -> list[dict]:
    """Run one pattern over a temporary project and return its records."""
    with tempfile.TemporaryDirectory(prefix="ubs_pyprec_") as tmp:
        paths = []
        for name, body in sources.items():
            target = Path(tmp) / name
            target.write_text(textwrap.dedent(body), encoding="utf-8")
            paths.append(target)
        sink = _Sink()
        scan_patterns([pattern(rule_id)], paths, sink, skip=set())
    return sink.records


def run_detector(module, sources: dict[str, str]) -> list[tuple]:
    with tempfile.TemporaryDirectory(prefix="ubs_pyprec_") as tmp:
        paths = []
        for name, body in sources.items():
            target = Path(tmp) / name
            target.write_text(textwrap.dedent(body), encoding="utf-8")
            paths.append(target)
        return list(module.find(paths))


class MissingReturnOrderingTests(unittest.TestCase):
    def test_reversed_inputs_preserve_deficit_and_exact_source_sites(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_missing_returns_") as tmp:
            first = Path(tmp) / "a.py"
            last = Path(tmp) / "z.py"
            first.write_text(
                "def alpha():\n    pass\n\ndef beta():\n    pass\n",
                encoding="utf-8",
            )
            last.write_text(
                "def zeta():\n    return 1\n\ndef omega():\n    return 2\n",
                encoding="utf-8",
            )
            expected = [
                (first, 1, 1, "def alpha():"),
                (first, 4, 1, "def beta():"),
            ]
            for paths in ([first, last], [last, first], [first]):
                with self.subTest(paths=paths):
                    self.assertEqual(list(missing_returns.find(paths)), expected)
            self.assertEqual(list(missing_returns.find([last])), [])
            self.assertEqual(list(missing_returns.find([])), [])

    def test_cli_corpus_single_deficit_keeps_identity_when_reversed(self) -> None:
        root = REPO_ROOT / "test-suite" / "python" / "buggy"
        paths = sorted(root.glob("*.py"))
        self.assertGreater(len(paths), 1)
        expected = [(root / "bad_resources.py", 6, 1, "def read_config(path):")]
        self.assertEqual(list(missing_returns.find(paths)), expected)
        self.assertEqual(list(missing_returns.find(list(reversed(paths)))), expected)


# ────────────────────────────── division ──────────────────────────────
class PathlibIsNotDivisionTests(unittest.TestCase):
    CLEAN = '''
        from pathlib import Path

        BASE = Path("/srv")

        def build(rules_dir, name, args):
            fdir = Path(args.files_dir)
            rules_sub = rules_dir / "rules"
            parent = fdir.parent
            return [
                rules_sub / f"{name}.yml",
                rules_sub / name,
                BASE / name,
                Path.cwd() / name,
                parent / name,
                fdir.resolve() / name,
                get_cache_dir() / name,
            ]

        def get_cache_dir():
            return BASE
    '''

    def test_path_joins_are_not_divisions(self) -> None:
        self.assertEqual(run_detector(division, {"paths.py": self.CLEAN}), [])

    def test_real_variable_division_still_reported(self) -> None:
        hits = run_detector(division, {"math.py": '''
            def ratios(hits, total, counts, scale):
                a = hits / total
                b = sum(counts) / scale
                c = hits / counts[0]
                return a, b, c
        '''})
        self.assertEqual(len(hits), 3, hits)
        self.assertTrue(all(h[0].startswith("py.numeric.division") for h in hits))

    def test_fstring_denominator_is_not_a_divisor(self) -> None:
        # The legacy filter kept any denominator whose *text* began with a
        # letter, so `f"…"` looked like a variable named `f`.
        hits = run_detector(division, {"fmt.py": '''
            def build(base, name):
                return base / f"{name}.yml"
        '''})
        self.assertEqual(hits, [])

    def test_ladder_promotes_to_warning_above_threshold(self) -> None:
        body = "def f(n, d):\n    return (\n" + "".join(
            f"        n / d,  # {i}\n" for i in range(division.WARNING_ABOVE + 2)
        ) + "    )\n"
        hits = run_detector(division, {"many.py": body})
        self.assertGreater(len(hits), division.WARNING_ABOVE)
        self.assertTrue(all(h[0] == "py.numeric.division-heavy" for h in hits))


# ─────────────────────────── index arithmetic ───────────────────────────
class IndexArithmeticGuardTests(unittest.TestCase):
    GUARDED = '''
        MARKER = "x"

        def inline_and(i, line):
            if i + 1 < len(line) and line[i + 1] == "/":
                return True
            return False

        def chained(idx, lines):
            return 0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]

        def enclosing_if(i, line):
            if i + 1 < len(line):
                return line[i + 1]
            return ""

        def or_case_split(idx, text):
            return idx == 0 or text[idx - 1] != "_"

        def one_based(lines):
            for idx, _ in enumerate(lines, start=1):
                yield lines[idx - 1]

        def ranged(x):
            for i in range(len(x) - 1):
                yield x[i + 1]

        def ranged_from_one(x, n):
            for i in range(1, n):
                yield x[i - 1]

        def early_exit(index, lines):
            start = index
            for _ in range(8):
                if start <= 0:
                    break
                if lines[start - 1].strip():
                    return start
                start -= 1
            return ""

        def truthiness(start, lines):
            return lines[start - 1] if start else ""

        def truthy_statement(start, lines):
            if not start:
                return ""
            return lines[start - 1]

        def caught(x, i):
            try:
                return x[i + 1]
            except IndexError:
                return None

        def ternary_guard(i, x):
            return x[i + 1] if i + 1 < len(x) else None

        def comprehension(x, n):
            return [x[i + 1] for i in range(n) if i + 1 < len(x)]

        def while_guard(i, s):
            while i + 1 < len(s):
                if s[i + 1] == "a":
                    return i
                i += 1
            return -1

        def asserted(i, x):
            assert i + 1 < len(x)
            return x[i + 1]
    '''

    UNGUARDED = '''
        def neighbours(x, i, j, k):
            a = x[i + 1]
            b = x[j - 1]
            c = x[k + 2]
            return a, b, c

        def argv_value(args):
            i = args.index("--root")
            return args[i + 1]

        def plain_enumerate(seq):
            for i, _ in enumerate(seq):
                yield seq[i - 1]
    '''

    def test_guarded_offsets_are_silent(self) -> None:
        self.assertEqual(run_detector(index_arithmetic, {"guarded.py": self.GUARDED}), [])

    def test_terminal_guards_allow_work_before_exiting(self) -> None:
        for exit_statement in ('return None', 'raise ValueError("bad line")', 'continue', 'break'):
            with self.subTest(exit_statement=exit_statement):
                hits = run_detector(index_arithmetic, {"guard.py": f'''
                    def read(lines, indexes, rejected):
                        for line in indexes:
                            if not 0 < line <= len(lines):
                                rejected.append(line)
                                {exit_statement}
                            value = lines[line - 1]
                '''})
                self.assertEqual(hits, [])

    def test_nonterminal_guard_and_rebound_index_keep_findings(self) -> None:
        bodies = (
            'if not 0 < line <= len(lines):\n    rejected.append(line)',
            'if not 0 < line <= len(lines):\n    if stop:\n        return None',
            'if line <= 0:\n    return None\nline = 0',
            'assert line > 0\nline -= 10',
            'if line <= 0:\n    return None\nif stop:\n    line = 0',
        )
        for body in bodies:
            with self.subTest(body=body):
                source = 'def read(lines, line, rejected, stop):\n' + textwrap.indent(body, '    ')
                source += '\n    return lines[line - 1]\n'
                hits = run_detector(index_arithmetic, {"rebound.py": source})
                self.assertEqual(len(hits), 1, hits)

    def test_rebinding_inside_a_guarded_body_or_operand_keeps_findings(self) -> None:
        sources = (
            'def read(lines, line):\n    if line > 0:\n        line = 0\n        return lines[line - 1]',
            'def read(lines, line, stop):\n    if line <= 0:\n        return None\n    if stop:\n        line = 0\n        return lines[line - 1]',
            'def read(lines):\n    for line, _ in enumerate(lines, 1):\n        line = 0\n        return lines[line - 1]',
            'def read(lines, line):\n    return line > 0 and (line := 0) == 0 and lines[line - 1]',
            'def read(lines, line):\n    if line > 0:\n        lines[(line := 0)] += lines[line - 1]',
            'def read(lines, line, reset):\n    if line <= 0:\n        return None\n    if reset(line := 0):\n        return lines[line - 1]',
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(len(run_detector(index_arithmetic, {'body.py': source})), 1)

    def test_rebinding_on_an_exiting_branch_does_not_change_the_survivor(self) -> None:
        hits = run_detector(index_arithmetic, {'survivor.py': '''
            def read(lines, line, stop):
                if line > 0:
                    if stop:
                        if stop == 2:
                            line = 0
                            return None
                    return lines[line - 1]
        '''})
        self.assertEqual(hits, [])

    def test_assignment_rhs_uses_the_guarded_old_index(self) -> None:
        hits = run_detector(index_arithmetic, {'rhs.py': '''
            def read(lines, line):
                if line + 1 < len(lines):
                    value, line = lines[line + 1], line + 2
                return value
        '''})
        self.assertEqual(hits, [])

    def test_comprehension_guards_follow_evaluation_order(self) -> None:
        cases = (
            ('[x[i + 1] for i in range(n) if i + 1 < len(x)]', 0),
            ('[i for i in range(n) if i + 1 < len(x) if x[i + 1]]', 0),
            ('[i for i in range(n) if x[i + 1] if i + 1 < len(x)]', 1),
            ('[j for j in x[i + 1] if i + 1 < len(x)]', 1),
            ('[j for i in range(n) for j in x[i + 1] if i + 1 < len(x)]', 1),
            ('[j for i in range(n) if i + 1 < len(x) for j in x[i + 1]]', 0),
            ('{i: x[i + 1] for i in range(n) if i + 1 < len(x)}', 0),
            ('(x[i + 1] for i in range(n) if i + 1 < len(x))', 0),
            ('[x[i - 1] for i, _ in enumerate(x, 1) for i in range(n)]', 1),
            ('[j for i, _ in enumerate(x, 1) for i in range(n) for j in x[i - 1]]', 1),
            ('[j for i, _ in enumerate(x, 1) for j in x[i - 1]]', 0),
            ('[x[i - 1] for i, _ in enumerate(x, 1) if (i := 0) == 0]', 1),
            ('[i for i, _ in enumerate(x, 1) if (i := 0) or x[i - 1]]', 1),
            ('[j for i in range(n) if i + 1 < len(x) for j in range(n) if (i := len(x)) or x[i + 1]]', 1),
        )
        for expression, expected in cases:
            with self.subTest(expression=expression):
                hits = run_detector(index_arithmetic, {"ordered.py": f'''
                    def read(x, i, n):
                        return {expression}
                '''})
                self.assertEqual(len(hits), expected, (expression, hits))

    def test_truthiness_split_only_guards_the_true_branch(self) -> None:
        # `if not i:` proves i == 0 inside its own body — the opposite of a guard.
        hits = run_detector(index_arithmetic, {"branch.py": """
            def wrong_branch(i, x):
                if not i:
                    return x[i - 1]
                return x[i]

            def wrong_else(i, x):
                return x[i] if i else x[i - 1]

            def element_not_index(i, x):
                if x[i - 1]:
                    return x[i - 1]
                return None
        """})
        self.assertEqual(len(hits), 4, hits)

    def test_equality_only_guards_against_a_literal_boundary(self) -> None:
        # `idx == 0` is a boundary case split; `i == j` says nothing about range.
        hits = run_detector(index_arithmetic, {"eq.py": """
            def unrelated(i, j, x):
                if i == j:
                    return x[i - 1]
                return None

            def boundary(idx, text):
                return idx == 0 or text[idx - 1] != "_"
        """})
        self.assertEqual(len(hits), 1, hits)

    def test_boolean_guards_follow_short_circuit_outcomes(self) -> None:
        cases = (
            ('safe-and', 'i + 1 < len(x) and x[i + 1]', 0),
            ('unsafe-or', 'i + 1 < len(x) or x[i + 1]', 1),
            ('safe-or', 'i + 1 >= len(x) or x[i + 1]', 0),
            ('unsafe-and', 'i + 1 >= len(x) and x[i + 1]', 1),
            ('safe-not', 'not (i + 1 >= len(x)) and x[i + 1]', 0),
            ('unsafe-negated-or', 'not (i + 1 >= len(x)) or x[i + 1]', 1),
            ('safe-predecessor', 'i and x[i - 1]', 0),
            ('unsafe-zero', 'not i and x[i - 1]', 1),
            ('safe-zero-split', 'i == 0 or x[i - 1]', 0),
            ('unsafe-zero-split', 'i == 0 and x[i - 1]', 1),
            ('unsafe-forward-truthiness', 'i and x[i + 1]', 1),
            ('unsafe-large-predecessor', 'i and x[i - 2]', 1),
            ('unsafe-large-zero-split', 'i == 0 or x[i - 2]', 1),
            ('unsafe-nested-or', '(ready or i + 1 < len(x)) and x[i + 1]', 1),
            ('safe-nested-and', '(ready and i + 1 < len(x)) and x[i + 1]', 0),
            ('unsafe-false-chain', '0 <= i + 1 < len(x) or x[i + 1]', 1),
        )
        for label, expression, expected in cases:
            with self.subTest(case=label):
                hits = run_detector(index_arithmetic, {
                    'boolean.py': f'def probe(x, i, ready):\n    return {expression}\n',
                })
                self.assertEqual(len(hits), expected, (expression, hits))

    def test_enclosing_guards_use_the_selected_branch(self) -> None:
        cases = (
            ('unsafe-or-body', 'if ready or i + 1 < len(x):\n        return x[i + 1]', 1),
            ('safe-and-body', 'if ready and i + 1 < len(x):\n        return x[i + 1]', 0),
            ('unsafe-else', 'if i + 1 < len(x):\n        return None\n    else:\n        return x[i + 1]', 1),
            ('safe-else', 'if i + 1 >= len(x):\n        return None\n    else:\n        return x[i + 1]', 0),
            ('safe-ternary', 'return None if i + 1 >= len(x) else x[i + 1]', 0),
            ('unsafe-ternary', 'return None if i + 1 < len(x) else x[i + 1]', 1),
            ('unsafe-equality', 'if i == 0:\n        return x[i + 1]', 1),
            ('unsafe-call-argument', 'if check(i + 1 < len(x)):\n        return x[i + 1]', 1),
            ('unsafe-early-and', 'if ready and i + 1 >= len(x):\n        return None\n    return x[i + 1]', 1),
            ('safe-early-or', 'if ready or i + 1 >= len(x):\n        return None\n    return x[i + 1]', 0),
            ('safe-while', 'while i and x[i - 1]:\n        i -= 1', 0),
        )
        for label, body, expected in cases:
            with self.subTest(case=label):
                hits = run_detector(index_arithmetic, {
                    'branch.py': f'def probe(x, i, ready):\n    {body}\n',
                })
                self.assertEqual(len(hits), expected, (body, hits))

    def test_unguarded_offsets_are_reported(self) -> None:
        hits = run_detector(index_arithmetic, {"unguarded.py": self.UNGUARDED})
        self.assertEqual(len(hits), 5, hits)

    def test_private_nonempty_bisect_predecessors_are_in_bounds(self) -> None:
        # bisect_right returns 0..len(seq). For a nonempty builtin sequence,
        # both the -1 endpoint and the len(seq)-1 endpoint are valid indices.
        for initializer in ("[0, 4]", "(0, 4)", "[0] + [p for p in points]", "[0, *points]"):
            with self.subTest(initializer=initializer):
                hits = run_detector(index_arithmetic, {"predecessor.py": f"""
                    from bisect import bisect_right
                    def locate(points, position):
                        offsets = {initializer}
                        cursor = bisect_right(offsets, position)
                        return offsets[cursor - 1]
                """})
                self.assertEqual(hits, [])

    def test_bisect_import_aliases_preserve_the_bound(self) -> None:
        for imported, function in (
            ("from bisect import bisect_right as search", "search"),
            ("import bisect as search", "search.bisect_right"),
        ):
            with self.subTest(imported=imported):
                hits = run_detector(index_arithmetic, {"alias.py": f"""
                    {imported}
                    def locate(position):
                        offsets: list[int] = [0]
                        cursor = {function}(offsets, position)
                        return offsets[cursor - 1]
                """})
                self.assertEqual(hits, [])

    def test_empty_or_unknown_sequences_keep_bisect_findings(self) -> None:
        for initializer in ("[]", "()", "[p for p in points]", "[*points]", "points"):
            with self.subTest(initializer=initializer):
                hits = run_detector(index_arithmetic, {"empty.py": f"""
                    from bisect import bisect_right
                    def locate(points, position):
                        offsets = {initializer}
                        cursor = bisect_right(offsets, position)
                        return offsets[cursor - 1]
                """})
                self.assertEqual(len(hits), 1, hits)

    def test_bisect_shadowing_does_not_prove_a_bound(self) -> None:
        for imported, parameters, statement in (
            ("from other import bisect_right", "position", "pass"),
            ("from bisect import bisect_right", "position, bisect_right", "pass"),
            ("from bisect import bisect_right", "position", "bisect_right = lambda *_: 99"),
            ("from bisect import bisect_right", "position", "def bisect_right(*args): return 99"),
            ("from bisect import bisect_right", "position", "from other import bisect_right"),
            ("from bisect import bisect_right", "position", "match position:\n                            case {'search': bisect_right}: pass"),
        ):
            with self.subTest(imported=imported, parameters=parameters, statement=statement):
                hits = run_detector(index_arithmetic, {"shadow.py": f"""
                    {imported}
                    def locate({parameters}):
                        {statement}
                        offsets = [0]
                        cursor = bisect_right(offsets, position)
                        return offsets[cursor - 1]
                """})
                self.assertEqual(len(hits), 1, hits)

    def test_bisect_module_mutation_and_escape_keep_findings(self) -> None:
        for mutation in (
            "search.bisect_right = lambda *_: 99",
            "setattr(search, 'bisect_right', lambda *_: 99)",
            "alias = search; alias.bisect_right = lambda *_: 99",
            "replace_function(search)",
        ):
            with self.subTest(mutation=mutation):
                hits = run_detector(index_arithmetic, {"module.py": f"""
                    import bisect as search
                    {mutation}
                    def locate(position):
                        offsets = [0]
                        cursor = search.bisect_right(offsets, position)
                        return offsets[cursor - 1]
                """})
                self.assertEqual(len(hits), 1, hits)

    def test_bisect_import_from_another_scope_is_not_a_binding(self) -> None:
        hits = run_detector(index_arithmetic, {"scope.py": """
            def unrelated():
                from bisect import bisect_right
            def locate(position):
                offsets = [0]
                cursor = bisect_right(offsets, position)
                return offsets[cursor - 1]
        """})
        self.assertEqual(len(hits), 1, hits)

    def test_mutating_another_bisect_alias_invalidates_the_import(self) -> None:
        for imported, function in (
            ("import bisect as search", "search.bisect_right"),
            ("from bisect import bisect_right", "bisect_right"),
        ):
            with self.subTest(imported=imported):
                hits = run_detector(index_arithmetic, {"other_alias.py": f"""
                    import bisect as other
                    other.bisect_right = lambda *_: 99
                    {imported}
                    def locate(position):
                        offsets = [0]
                        cursor = {function}(offsets, position)
                        return offsets[cursor - 1]
                """})
                self.assertEqual(len(hits), 1, hits)

    def test_sequence_mutation_or_escape_invalidates_bisect_proof(self) -> None:
        for before, after in (
            ("pass", "offsets.clear()"),
            ("alias = offsets", "alias.clear()"),
            ("pass", "del offsets[:]"),
            ("pass", "offsets = []"),
            ("expose(offsets)", ""),
            ("def clear(): offsets.clear()", ""),
        ):
            with self.subTest(before=before, after=after):
                hits = run_detector(index_arithmetic, {"mutation.py": f"""
                    from bisect import bisect_right
                    def locate(position):
                        offsets = [0]
                        {before}
                        cursor = bisect_right(offsets, position)
                        {after}
                        return offsets[cursor - 1]
                """})
                self.assertEqual(len(hits), 1, hits)

    def test_bisect_optional_bounds_and_different_sequences_keep_findings(self) -> None:
        for arguments, lookup in (
            ("offsets, position, 0, 99", "offsets"),
            ("offsets, position, hi=99", "offsets"),
            ("offsets, position", "other"),
        ):
            with self.subTest(arguments=arguments, lookup=lookup):
                hits = run_detector(index_arithmetic, {"bounds.py": f"""
                    from bisect import bisect_right
                    def locate(position, other):
                        offsets = [0]
                        cursor = bisect_right({arguments})
                        return {lookup}[cursor - 1]
                """})
                self.assertEqual(len(hits), 1, hits)

    def test_callback_cannot_change_bisect_index_before_lookup(self) -> None:
        hits = run_detector(index_arithmetic, {"callback.py": """
            from bisect import bisect_right
            def locate(position):
                offsets = [0]
                def change():
                    nonlocal cursor
                    cursor = 99
                cursor = bisect_right(offsets, position)
                return change(), offsets[cursor - 1]
        """})
        self.assertEqual(len(hits), 1, hits)

    def test_list_membership_does_not_prove_an_index_bound(self) -> None:
        hits = run_detector(index_arithmetic, {"membership.py": """
            def wrong(values, cursor):
                if cursor - 1 in values:
                    return values[cursor - 1]
        """})
        self.assertEqual(len(hits), 1, hits)

    def test_ladder_promotes_to_warning_above_threshold(self) -> None:
        body = "def f(x, i):\n    return (\n" + "".join(
            f"        x[i + {n}],\n" for n in range(1, index_arithmetic.WARNING_ABOVE + 3)
        ) + "    )\n"
        hits = run_detector(index_arithmetic, {"many.py": body})
        self.assertGreater(len(hits), index_arithmetic.WARNING_ABOVE)
        self.assertTrue(all(h[0] == "py.collections.index-arithmetic" for h in hits))

    def test_collected_one_based_indices_retain_their_lower_bound(self) -> None:
        case = "index-collected-enumerate-clean"
        started = time.perf_counter()
        print(f"[{case}] RUN", flush=True)
        source = """
            def selected(lines):
                indices: list[int] = []
                for index, line in enumerate(lines, 1):
                    if line.strip():
                        indices.append(index)
                if not indices:
                    return
                for index in indices:
                    yield lines[index - 1]
        """
        hits = run_detector(index_arithmetic, {"collected.py": source})
        print(f"[{case}] {'PASS' if not hits else 'FAIL'} ({time.perf_counter() - started:.3f}s)", flush=True)
        self.assertEqual(hits, [], (source, hits))

    def test_unproved_collected_indices_still_reach_warning_tier(self) -> None:
        cases = (
            ("zero-based", "", "enumerate(lines)", "", "index", "", ""),
            ("value-not-index", "", "enumerate(lines, 1)", "", "line", "", ""),
            ("rebound-collector", "", "enumerate(lines, 1)", "index = 0", "index", "", ""),
            ("escaped-list", "", "enumerate(lines, 1)", "", "index", "other = indices; other.append(0)", ""),
            ("extra-write", "", "enumerate(lines, 1)", "", "index", "indices.append(0)", ""),
            ("rebound-list", "", "enumerate(lines, 1)", "", "index", "indices = [0]", ""),
            ("rebound-reader", "", "enumerate(lines, 1)", "", "index", "", "index = 0"),
            ("shadowed-enumerate", ", enumerate", "enumerate(lines, 1)", "", "index", "", ""),
        )
        for label, parameter, iterator, before_append, value, after_collect, before_read in cases:
            case = f"index-collected-enumerate-{label}"
            started = time.perf_counter()
            print(f"[{case}] RUN", flush=True)
            with self.subTest(case=label):
                body = [f"def selected(lines{parameter}):", "    indices = []",
                        f"    for index, line in {iterator}:"]
                if before_append:
                    body.append(f"        {before_append}")
                body.append(f"        indices.append({value})")
                if after_collect:
                    body.append(f"    {after_collect}")
                body.append("    for index in indices:")
                if before_read:
                    body.append(f"        {before_read}")
                body.extend(["        yield lines[index - 1]"] * 13)
                source = "\n".join(body) + "\n"
                hits = run_detector(index_arithmetic, {"unproved.py": source})
                passed = len(hits) == 13 and all(hit[0] == "py.collections.index-arithmetic" for hit in hits)
                print(f"[{case}] {'PASS' if passed else 'FAIL'} ({time.perf_counter() - started:.3f}s)", flush=True)
                self.assertEqual(len(hits), 13, (source, hits))
                self.assertTrue(all(hit[0] == "py.collections.index-arithmetic" for hit in hits), hits)

    def test_below_threshold_is_the_info_tier(self) -> None:
        hits = run_detector(index_arithmetic, {"few.py": "def f(x, i):\n    return x[i + 1]\n"})
        self.assertEqual([h[0] for h in hits], ["py.collections.index-arithmetic-info"])

    def test_marker_suppresses_and_leaves_the_count(self) -> None:
        hits = run_detector(index_arithmetic, {"marked.py": '''
            def f(x, i):
                # ubs:ignore[py.collections.index-arithmetic]
                return x[i + 1]
        '''})
        self.assertEqual(hits, [])

    def test_string_and_comment_shapes_are_not_code(self) -> None:
        hits = run_detector(index_arithmetic, {"docs.py": '''
            """Explains chars[i + 1] and lines[idx - 1] in prose."""
            PATTERN = r"\\[[A-Za-z_]+ *[+-] *[0-9]+\\]"
            # a comment about buf[n + 1]
        '''})
        self.assertEqual(hits, [])


# ─────────────────────────────── open() ───────────────────────────────
class OpenMissingWithTests(unittest.TestCase):
    def test_prose_about_open_is_not_a_handle(self) -> None:
        hits = run_detector(io_open_checks, {"prose.py": '''
            """Tracks handles created by ``tarfile.open()`` and open()."""
            import re
            OPEN_RE = re.compile(r"open\\(")
            # legacy counted every open( on the line
        '''})
        self.assertEqual(hits, [])

    def test_with_managed_handles_are_clean(self) -> None:
        hits = run_detector(io_open_checks, {"managed.py": '''
            import contextlib
            from pathlib import Path

            def read(p):
                with open(p, encoding="utf-8") as fh:
                    return fh.read()

            def read_path(p: Path):
                with p.open(encoding="utf-8") as fh:
                    return fh.read()

            def read_closing(p):
                with contextlib.closing(open(p, encoding="utf-8")) as fh:
                    return fh.read()

            def read_explicit(p):
                fh = open(p, encoding="utf-8")
                try:
                    return fh.read()
                finally:
                    fh.close()
        '''})
        self.assertEqual(hits, [])

    def test_unmanaged_handle_is_reported(self) -> None:
        hits = run_detector(io_open_checks, {"leak.py": '''
            import json

            def read(p):
                return open(p, encoding="utf-8").read()

            def load(p):
                return json.load(open(p, encoding="utf-8"))
        '''})
        self.assertEqual(len(hits), 2, hits)

    def test_exitstack_owns_the_exact_os_descriptor(self) -> None:
        for imports, allocation, close, stack in (
            ('import os, contextlib', 'os.open', 'os.close', 'contextlib.ExitStack'),
            ('import os as posix\nimport contextlib as contexts',
             'posix.open', 'posix.close', 'contexts.ExitStack'),
            ('from os import open as allocate, close as release\nfrom contextlib import ExitStack as Stack',
             'allocate', 'release', 'Stack'),
        ):
            source = (imports + '\ndef operation(path):\n'
                      f'    with {stack}() as resources:\n'
                      f'        descriptor = {allocation}(path, 0)\n'
                      f'        resources.callback({close}, descriptor)\n'
                      '        perform_operation(descriptor)\n')
            with self.subTest(imports=imports):
                self.assertEqual(run_detector(io_open_checks, {'owned.py': source}), [])
                unowned = source.replace(f'        resources.callback({close}, descriptor)\n', '')
                self.assertEqual(len(run_detector(io_open_checks, {'unowned.py': unowned})), 1)

    def test_exitstack_descriptor_requires_real_unescaped_ownership(self) -> None:
        original = ('import os, contextlib\ndef operation(path):\n'
                    '    with contextlib.ExitStack() as resources:\n'
                    '        descriptor = os.open(path, 0)\n'
                    '        resources.callback(os.close, descriptor)\n')
        for source in (
            original.replace('contextlib.ExitStack()', 'unknown_stack()'),
            original.replace('callback(os.close, descriptor)', 'callback(unknown_close, descriptor)'),
            original.replace('callback(os.close, descriptor)', 'callback(os.close, other_descriptor)'),
            original + '        resources.pop_all()\n',
            original + '        escape(resources)\n',
            original.replace('def operation(path):', 'def operation(path, contextlib):'),
            original.replace('def operation(path):', 'contextlib = unknown\ndef operation(path):'),
            original.replace('def operation(path):', 'os.close = unknown_close\ndef operation(path):'),
            original.replace('def operation(path):', 'modify_module(os)\ndef operation(path):'),
            original.replace('contextlib.ExitStack() as resources:',
                             'contextlib.ExitStack() as resources, unknown_stack() as resources:'),
            original.replace('        resources.callback', '        may_raise()\n        resources.callback'),
        ):
            with self.subTest(source=source):
                self.assertEqual(len(run_detector(io_open_checks, {'unsafe.py': source})), 1)

    def test_exitstack_owns_adjacent_nested_allocations(self) -> None:
        for body in (
            'for path in paths:\n    descriptor = os.open(path, 0)\n'
            '    resources.callback(os.close, descriptor)\n',
            'if paths:\n    descriptor = os.open(paths[0], 0)\n'
            '    resources.callback(os.close, descriptor)\n',
            'try:\n    descriptor = os.open(paths[0], 0)\n'
            '    resources.callback(os.close, descriptor)\nexcept OSError:\n    raise\n',
        ):
            source = ('import os, contextlib\ndef operation(paths):\n'
                      '    with contextlib.ExitStack() as resources:\n'
                      + textwrap.indent(body, '        '))
            with self.subTest(body=body):
                self.assertEqual(run_detector(io_open_checks, {'nested.py': source}), [])
                leaked = source.replace('            resources.callback(os.close, descriptor)\n', '')
                self.assertEqual(len(run_detector(io_open_checks, {'leaked.py': leaked})), 1)

    def test_nested_registration_cannot_mask_a_conditional_or_escaped_owner(self) -> None:
        for body in (
            'descriptor = os.open(path, 0)\nif ready:\n    resources.callback(os.close, descriptor)\n',
            'for path in paths:\n    descriptor = os.open(path, 0)\n'
            '    may_raise()\n    resources.callback(os.close, descriptor)\n',
            'for path in paths:\n    descriptor = os.open(path, 0)\n'
            '    resources.callback(os.close, descriptor)\nresources.pop_all()\n',
            'descriptor = os.open(path, 0)\ndef deferred():\n    resources.callback(os.close, descriptor)\n',
            'descriptor = os.open(path, 0)\n'
            'with contextlib.ExitStack() as resources:\n    resources.callback(os.close, descriptor)\n',
        ):
            source = ('import os, contextlib\ndef operation(paths, path, ready):\n'
                      '    with contextlib.ExitStack() as resources:\n'
                      + textwrap.indent(body, '        '))
            with self.subTest(body=body):
                self.assertEqual(len(run_detector(io_open_checks, {'unsafe.py': source})), 1)

    def test_fdopen_context_takes_ownership_of_the_same_descriptor(self) -> None:
        for imports, allocate, wrapper in (
            ('import os', 'os.open', 'os.fdopen'),
            ('import os as posix', 'posix.open', 'posix.fdopen'),
            ('from os import open as allocate, fdopen as wrap', 'allocate', 'wrap'),
        ):
            for options in ('', ', "rb"', ', mode="rb"', ', "rb", closefd=True'):
                source = (imports + '\ndef read(path):\n'
                          f'    descriptor = {allocate}(path, 0)\n'
                          f'    with {wrapper}(descriptor{options}) as handle:\n'
                          '        return handle.read()\n')
                with self.subTest(imports=imports, options=options):
                    self.assertEqual(run_detector(io_open_checks, {'owned.py': source}), [])

    def test_fdopen_requires_proven_immediate_ownership(self) -> None:
        original = ('import os\ndef read(path):\n'
                    '    descriptor = os.open(path, 0)\n'
                    '    with os.fdopen(descriptor, "rb") as handle:\n'
                    '        return handle.read()\n')
        for source in (
            original.replace('"rb")', '"rb", closefd=False)'),
            original.replace('"rb")', '"rb", closefd=setting)'),
            original.replace('"rb")', '"rb", **options)'),
            original.replace('"rb")', 'get_mode())'),
            original.replace('"rb")', '"invalid-mode")'),
            original.replace('os.fdopen(descriptor', 'os.fdopen(other_descriptor'),
            original.replace('os.fdopen(descriptor', 'unknown.fdopen(descriptor'),
            original.replace('with os.fdopen', 'with may_raise(), os.fdopen'),
            original.replace('    with os.fdopen', '    may_raise()\n    with os.fdopen'),
            original.replace('def read(path):', 'def read(path, os):'),
            original.replace('def read(path):', 'os.fdopen = unknown\ndef read(path):'),
            # An integer has no .close() method and cannot be a context manager.
            original.replace('    with os.fdopen(descriptor, "rb") as handle:\n'
                             '        return handle.read()\n', '    descriptor.close()\n'),
            original.replace('with os.fdopen(descriptor, "rb")', 'with descriptor'),
        ):
            with self.subTest(source=source):
                self.assertEqual(len(run_detector(io_open_checks, {'unsafe.py': source})), 1)

    def test_builtin_open_context_owns_the_inline_opener_descriptor(self) -> None:
        source = ('import os\ndef read(path):\n'
                  '    with open(path, "rb", opener=lambda name, flags: os.open(name, flags)) as handle:\n'
                  '        return handle.read()\n')
        self.assertEqual(run_detector(io_open_checks, {'owned.py': source}), [])
        for unsafe in (
            source.replace('def read(path):', 'def read(path, open):'),
            source.replace('def read(path):', 'from custom import open\ndef read(path):'),
            source.replace('def read(path):', 'open = custom\ndef read(path):'),
            source.replace('def read(path):', 'import builtins\nbuiltins.open = custom\ndef read(path):'),
            source.replace('os.open(name, flags)', 'consume(os.open(name, flags))'),
            source.replace('opener=lambda', 'closefd=False, opener=lambda'),
            source.replace('opener=lambda', '**options, opener=lambda'),
            'import os\nhandle = open(path, opener=lambda name, flags: os.open(name, flags))\n',
        ):
            with self.subTest(source=unsafe):
                self.assertEqual(len(run_detector(io_open_checks, {'unsafe.py': unsafe})), 1)

    def test_raw_descriptor_explicit_cleanup_preserves_real_leaks(self) -> None:
        cases = (
            ('adjacent_close', 'fd = os.open(path, 0)\nos.close(fd)\n', ()),
            ('annotated_close', 'fd: int = os.open(path, 0)\nos.close(fd)\n', ()),
            ('finally_close', 'fd = os.open(path, 0)\ntry:\n    consume(fd)\nfinally:\n    os.close(fd)\n', ()),
            ('finally_annotated', 'fd: int = os.open(path, 0)\ntry:\n    return os.read(fd, 10)\nfinally:\n    os.close(fd)\n', ()),
            ('allocate_in_try', 'try:\n    fd = os.open(path, 0)\n    consume(fd)\nfinally:\n    os.close(fd)\n', ()),
            ('exception_before_finally', 'fd = os.open(path, 0)\ntry:\n    raise ValueError("failed")\nexcept ValueError:\n    return\nfinally:\n    os.close(fd)\n', ()),
            ('after_cleanup_can_raise', 'fd = os.open(path, 0)\ntry:\n    consume(fd)\nfinally:\n    os.close(fd)\n    may_raise()\n', ()),
            ('borrowed_wrapper', 'fd = os.open(path, 0)\ntry:\n    with os.fdopen(fd, "rb", closefd=False) as handle:\n        consume(handle)\nfinally:\n    os.close(fd)\n', ()),
            ('copied_value_keeps_original', 'fd = os.open(path, 0)\ntry:\n    captured = fd\n    consume(captured)\nfinally:\n    os.close(fd)\n', ()),
            ('conditional_close', 'fd = os.open(path, 0)\nif ready:\n    os.close(fd)\n', (3,)),
            ('conditional_finally', 'fd = os.open(path, 0)\ntry:\n    consume(fd)\nfinally:\n    if ready:\n        os.close(fd)\n', (3,)),
            ('wrong_descriptor', 'fd = os.open(path, 0)\ntry:\n    consume(fd)\nfinally:\n    os.close(other)\n', (3,)),
            ('reassigned_descriptor', 'fd = os.open(path, 0)\ntry:\n    fd = other\nfinally:\n    os.close(fd)\n', (3,)),
            ('exception_rebinds_descriptor', 'fd = os.open(path, 0)\ntry:\n    consume(fd)\nexcept Exception as fd:\n    pass\nfinally:\n    os.close(fd)\n', (3,)),
            ('import_rebinds_descriptor', 'fd = os.open(path, 0)\ntry:\n    from application import fd\nfinally:\n    os.close(fd)\n', (3,)),
            ('pattern_rebinds_descriptor', 'fd = os.open(path, 0)\ntry:\n    match other:\n        case fd:\n            pass\nfinally:\n    os.close(fd)\n', (3,)),
            ('pattern_star_rebinds_descriptor', 'fd = os.open(path, 0)\ntry:\n    match other:\n        case [*fd]:\n            pass\nfinally:\n    os.close(fd)\n', (3,)),
            ('pattern_mapping_rebinds_descriptor', 'fd = os.open(path, 0)\ntry:\n    match other:\n        case {"key": value, **fd}:\n            pass\nfinally:\n    os.close(fd)\n', (3,)),
            ('raise_before_cleanup', 'fd = os.open(path, 0)\ntry:\n    consume(fd)\nfinally:\n    may_raise()\n    os.close(fd)\n', (3,)),
            ('captured_original_leaks', 'fd = os.open(path, 0)\ntry:\n    captured = fd\n    fd = other\nfinally:\n    os.close(fd)\n', (3,)),
            ('only_second_allocation_closed', 'first = os.open(path, 0)\nfd = os.open(path, 0)\nos.close(fd)\n', (3,)),
            ('borrowed_wrapper_leaks', 'fd = os.open(path, 0)\nwith os.fdopen(fd, "rb", closefd=False) as handle:\n    consume(handle)\n', (3,)),
            ('closure_rebinds_descriptor', 'fd = -1\ndef replace():\n    nonlocal fd\n    fd = other\nfd = os.open(path, 0)\ntry:\n    replace()\nfinally:\n    os.close(fd)\n', (7,)),
            ('frame_rebinds_descriptor', 'fd = os.open(path, 0)\ntry:\n    frame.f_locals["fd"] = other\nfinally:\n    os.close(fd)\n', (3,)),
        )
        for name, body, expected in cases:
            source = ('import os\ndef operation(path, other, ready):\n'
                      + textwrap.indent(body, '    '))
            with self.subTest(case=name):
                hits = run_detector(io_open_checks, {name + '.py': source})
                self.assertEqual(tuple(row[1] for row in hits), expected, hits)

    def test_explicit_descriptor_cleanup_resolves_imports(self) -> None:
        for imports, allocate, release in (
            ('import os', 'os.open', 'os.close'),
            ('import os as posix', 'posix.open', 'posix.close'),
            ('from os import open as allocate, close as release', 'allocate', 'release'),
        ):
            for cleanup in ('{release}(fd)\n',
                            'try:\n    consume(fd)\nfinally:\n    {release}(fd)\n'):
                source = (imports + '\ndef operation(path):\n'
                          f'    fd = {allocate}(path, 0)\n'
                          + textwrap.indent(cleanup.format(release=release), '    '))
                with self.subTest(imports=imports, cleanup=cleanup):
                    self.assertEqual(run_detector(io_open_checks, {'owned.py': source}), [])
        shadowed = ('import os\nos.close = unknown\ndef operation(path):\n'
                    '    fd = os.open(path, 0)\n'
                    '    try:\n        consume(fd)\n    finally:\n        os.close(fd)\n')
        self.assertEqual(tuple(row[1] for row in run_detector(io_open_checks, {'shadowed.py': shadowed})), (4,))

    def test_descriptor_import_order_on_one_line(self) -> None:
        for imports, allocate, release in (
            ('import os', 'os.open', 'os.close'),
            ('import os as posix', 'posix.open', 'posix.close'),
            ('from os import open as allocate, close as release', 'allocate', 'release'),
        ):
            for cleanup, expected in ((f'{release}(fd)', ()), ('fd.close()', (1,))):
                source = f'{imports}; fd = {allocate}(path, 0); {cleanup}\n'
                with self.subTest(imports=imports, cleanup=cleanup):
                    hits = run_detector(io_open_checks, {'one_line.py': source})
                    self.assertEqual(tuple(row[1] for row in hits), expected, hits)

    def test_descriptor_cleanup_import_must_be_visible_and_executed(self) -> None:
        cases = (
            ('unrelated_function', 'def unrelated():\n    from os import close as release\n', '', (6,)),
            ('conditional_import', 'if False:\n    from os import close as release\n', '', (6,)),
            ('unrelated_class', 'class Other:\n    from os import close as release\n', '', (6,)),
            ('local_import', '', '    from os import close as release\n', ()),
        )
        for name, before, local, expected in cases:
            source = ('import os, contextlib\n' + before + 'def operation(path):\n' + local
                      + '    with contextlib.ExitStack() as resources:\n'
                      '        fd = os.open(path, 0)\n'
                      '        resources.callback(release, fd)\n')
            with self.subTest(case=name):
                hits = run_detector(io_open_checks, {name + '.py': source})
                self.assertEqual(tuple(row[1] for row in hits), expected, hits)
        late = ('import os, contextlib\ndef operation(path):\n'
                '    with contextlib.ExitStack() as resources:\n'
                '        fd = os.open(path, 0)\n'
                '        resources.callback(release, fd)\n'
                '    from os import close as release\n')
        self.assertEqual(tuple(row[1] for row in run_detector(io_open_checks, {'late.py': late})), (4,))

    def test_descriptor_cleanup_rejects_shadowed_closer(self) -> None:
        cases = (
            ('late_local_shadow', 'def work(path):\n    with contextlib.ExitStack() as stack:\n        fd = os.open(path, 0)\n        stack.callback(release, fd)\n    from os import close as release\n', 5),
            ('conditional_local_shadow', 'def work(path):\n    if False:\n        from os import close as release\n    with contextlib.ExitStack() as stack:\n        fd = os.open(path, 0)\n        stack.callback(release, fd)\n', 7),
            ('exception_capture', 'def work(path):\n    try:\n        raise ValueError()\n    except Exception as release:\n        with contextlib.ExitStack() as stack:\n            fd = os.open(path, 0)\n            stack.callback(release, fd)\n', 8),
            ('match_capture', 'def work(path, other):\n    match other:\n        case release:\n            with contextlib.ExitStack() as stack:\n                fd = os.open(path, 0)\n                stack.callback(release, fd)\n', 7),
            ('star_capture', 'def work(path, other):\n    match other:\n        case [*release]:\n            with contextlib.ExitStack() as stack:\n                fd = os.open(path, 0)\n                stack.callback(release, fd)\n', 7),
            ('mapping_capture', 'def work(path, other):\n    match other:\n        case {"key": value, **release}:\n            with contextlib.ExitStack() as stack:\n                fd = os.open(path, 0)\n                stack.callback(release, fd)\n', 7),
            ('star_import', 'from unknown import *\nwith contextlib.ExitStack() as stack:\n    fd = os.open(path, 0)\n    stack.callback(release, fd)\n', 5),
        )
        for name, body, line in cases:
            source = 'import os, contextlib\nfrom os import close as release\n' + body
            with self.subTest(case=name):
                hits = run_detector(io_open_checks, {name + '.py': source})
                self.assertEqual(tuple(row[1] for row in hits), (line,), hits)


# ─────────────────────── json.loads without a handler ───────────────────────
class OpenNoEncodingCalleeTests(unittest.TestCase):
    """py.io.open-no-encoding is about open(), not names ending in "open" (#167)."""

    def test_callees_that_end_in_open_are_not_file_opens(self) -> None:
        records = run_patterns("py.io.open-no-encoding", {"p.py": '''
            import os
            import subprocess
            from urllib.request import urlopen

            def run(argv, url, fd):
                with open("out.log", "w", encoding="utf-8") as out:
                    proc = subprocess.Popen(argv, stdout=out)
                body = urlopen(url)
                pipe = os.popen("ls")
                handle = os.fdopen(fd)
                return proc.wait(), body, pipe, handle
        '''})
        self.assertEqual(records, [])

    def test_open_and_open_methods_without_encoding_are_still_reported(self) -> None:
        records = run_patterns("py.io.open-no-encoding", {"o.py": '''
            import pathlib

            def read(path):
                first = open(path).read()
                second = pathlib.Path(path).open().read()
                return first, second
        '''})
        self.assertEqual(sorted(record["line"] for record in records), [5, 6], records)


class JsonLoadsGuardTests(unittest.TestCase):
    """`py.parsing.json-loads-no-try` after the #109 §3 deduplication.

    The ast-grep twin `py.json.loads-no-try` was removed because it reported
    every call this detector already did. It was right about one thing the
    detector was not — a `try` is only error handling if it has an `except` —
    so that moved here, and these pin both halves.
    """

    def test_the_detector_is_the_only_json_loads_rule(self) -> None:
        from ubs_core.py_rules import _RULES

        rules = dict(_RULES)
        self.assertNotIn("json-loads-no-try", rules,
                         "the ast-grep twin is back; it double-counts the detector")
        declared = {line.split(":", 1)[1].strip()
                    for source in rules.values()
                    for line in source.splitlines()
                    if line.startswith("id:")}
        self.assertNotIn("py.json.loads-no-try", declared)
        # `json.load` is a different function and keeps its own rule.
        self.assertIn("py.json-load-no-try", declared)

    def test_try_with_except_still_guards(self) -> None:
        hits = run_detector(json_loads, {"guarded.py": '''
            import json

            def f(s):
                try:
                    return json.loads(s)
                except ValueError:
                    return None
        '''})
        self.assertEqual(hits, [])

    def test_try_without_except_is_not_error_handling(self) -> None:
        """try/finally guarantees cleanup, not a caught JSONDecodeError."""
        hits = run_detector(json_loads, {"finally_only.py": '''
            import json

            def f(s, lock):
                try:
                    return json.loads(s)
                finally:
                    lock.release()
        '''})
        self.assertEqual(len(hits), 1, hits)

    def test_handler_and_finally_bodies_are_not_protected_by_their_own_try(self) -> None:
        """An exception raised there propagates past handlers already chosen."""
        hits = run_detector(json_loads, {"bodies.py": '''
            import json

            def in_handler(s):
                try:
                    pass
                except ValueError:
                    return json.loads(s)

            def in_finally(s):
                try:
                    pass
                except ValueError:
                    pass
                finally:
                    return json.loads(s)

            def in_orelse(s):
                try:
                    pass
                except ValueError:
                    pass
                else:
                    return json.loads(s)
        '''})
        self.assertEqual(len(hits), 3, hits)

    def test_an_outer_try_still_guards_an_inner_finally(self) -> None:
        """The walk continues outward instead of stopping at the first Try."""
        hits = run_detector(json_loads, {"nested.py": '''
            import json

            def f(s, lock):
                try:
                    try:
                        pass
                    finally:
                        return json.loads(s)
                except ValueError:
                    return None
        '''})
        self.assertEqual(hits, [])

    def test_suppression_marker_is_honoured(self) -> None:
        hits = run_detector(json_loads, {"quiet.py": '''
            import json

            def f(s):
                return json.loads(s)  # ubs:ignore
        '''})
        self.assertEqual(hits, [])


# ───────────────────────────── is <literal> ─────────────────────────────
class IsLiteralSingletonTests(unittest.TestCase):
    def test_bool_singletons_are_idiomatic(self) -> None:
        hits = run_detector(is_literal, {"tri.py": '''
            def truthy(value):
                return value is True or value == 1

            def falsy(value):
                return value is False or value is None
        '''})
        self.assertEqual(hits, [])

    def test_other_literals_still_reported(self) -> None:
        hits = run_detector(is_literal, {"lit.py": '''
            def classify(status, code, values):
                if status is "ready":
                    return 1
                if code is 200:
                    return 2
                if values is []:
                    return 3
                return 0
        '''})
        self.assertEqual(len(hits), 3, hits)

    def test_the_detector_is_the_only_is_literal_rule(self) -> None:
        """One defect, one id. The ast-grep twin was a pure double count.

        `py.is-literal` matched `$X is 0` / `is 1` / `is -1` — a strict subset
        of what this detector reports — so every hit it produced was a second
        report of a finding already made under `py.comparison.is-literal`
        (GH #109 §3). Deleting it cost no coverage; the subset assertion below
        is what makes that checkable rather than asserted.
        """
        from ubs_core.py_rules import _RULES

        rules = dict(_RULES)
        self.assertNotIn("is-literal", rules,
                         "the ast-grep twin is back; it double-counts the detector")
        declared = {line.split(":", 1)[1].strip()
                    for source in rules.values()
                    for line in source.splitlines()
                    if line.startswith("id:")}
        self.assertNotIn("py.is-literal", declared)

        # Everything the removed rule could match, the detector still reports.
        hits = run_detector(is_literal, {"subset.py": '''
            def f(x):
                a = x is 0
                b = x is 1
                c = x is -1
                return a, b, c
        '''})
        self.assertEqual(len(hits), 3, hits)


# ─────────────────────── pattern layer: string masking ───────────────────────
class PatternStringMaskingTests(unittest.TestCase):
    RULE_TABLE = '''
        """A rule table: the snippets below are data, not code."""
        RULES = (
            "- pattern: $X == None",
            "- pattern: os.system($$$)",
            "- pattern: hashlib.md5($$$)",
            'message: "Use isinstance(x, T) instead of type(x) == T"',
            ("TODO", "FIXME", "HACK", "XXX"),
        )
    '''

    def test_snippets_in_literals_are_not_code(self) -> None:
        for rule_id in ("py.none.equality", "py.modules.os-system",
                        "py.security.weak-hash", "py.comparison.type-equality",
                        "py.code-quality.tech-debt"):
            with self.subTest(rule=rule_id):
                self.assertEqual(run_patterns(rule_id, {"rules.py": self.RULE_TABLE}), [])

    def test_real_code_still_matches(self) -> None:
        source = '''
            import hashlib
            import os

            def go(x, value):
                if value == None:
                    os.system("ls")
                return hashlib.md5(x).hexdigest(), type(x) == int
        '''
        for rule_id in ("py.none.equality", "py.modules.os-system",
                        "py.security.weak-hash", "py.comparison.type-equality"):
            with self.subTest(rule=rule_id):
                self.assertTrue(run_patterns(rule_id, {"live.py": source}), rule_id)

    def test_tech_debt_still_reads_comments(self) -> None:
        records = run_patterns("py.code-quality.tech-debt", {"c.py": '''
            def f():
                # TODO: finish this
                return 1  # FIXME later
        '''})
        self.assertEqual(len(records), 2, records)

    def test_masking_keeps_line_numbers_and_raw_samples(self) -> None:
        records = run_patterns("py.none.equality", {"n.py": '''
            def f(value):
                if value == None:
                    return 0
                return 1
        '''})
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["line"], 3)
        self.assertIn("value == None", records[0]["message"])

    def test_notebook_json_is_not_masked_as_python(self) -> None:
        records = run_patterns("py.notebooks.outputs-embedded", {
            # One match per line: the scan counts distinct matching lines.
            "nb.ipynb": '{"cells": [\n' + '  {"outputs": [{"a": 1}]},\n' * 7 + "]}"
        })
        self.assertTrue(records)


class DeprecatedImpBoundaryTests(unittest.TestCase):
    def test_importlib_is_not_the_removed_imp_module(self) -> None:
        records = run_patterns("py.deprecations.deprecated-api", {"i.py": "import importlib\n"})
        self.assertEqual(records, [])

    def test_real_imp_import_still_reported(self) -> None:
        for source in ("import imp\n", "import imp as legacy\n", "from imp import reload\n",
                       "loop = asyncio.get_event_loop()\n"):
            with self.subTest(source=source.strip()):
                self.assertTrue(run_patterns("py.deprecations.deprecated-api", {"i.py": source}))


# ───────────────────────────── py.debug.print ─────────────────────────────
class DebugPrintCliRoleTests(unittest.TestCase):
    MANY_PRINTS = "".join(f'    print("line {i}")\n' for i in range(60))

    def test_cli_entry_point_may_print(self) -> None:
        for header in (
            "#!/usr/bin/env python3\ndef main():\n",
            "import argparse\ndef main():\n",
            "import sys\ndef main():\n    _ = sys.argv\n",
            'def main():\n    pass\nif __name__ == "__main__":\n    main()\ndef other():\n',
        ):
            with self.subTest(header=header.splitlines()[0]):
                records = run_patterns("py.debug.print", {"cli.py": header + self.MANY_PRINTS})
                self.assertEqual(records, [], header)

    def test_library_module_still_reported(self) -> None:
        records = run_patterns("py.debug.print", {"lib.py": "def emit():\n" + self.MANY_PRINTS})
        self.assertEqual(len(records), 60)
        self.assertTrue(all(r["severity"] == "warning" for r in records))

    def test_prose_about_argv_does_not_fake_a_cli_role(self) -> None:
        # The role test runs on the string-blanked view for exactly this case:
        # a docstring that *mentions* argparse/sys.argv/__main__ is not a CLI.
        source = (
            '"""A library module: no argparse, no sys.argv, no __main__ guard."""\n'
            "def emit():\n" + self.MANY_PRINTS
        )
        self.assertEqual(len(run_patterns("py.debug.print", {"lib.py": source})), 60)

    def test_print_inside_a_docstring_is_not_a_statement(self) -> None:
        records = run_patterns("py.debug.print", {"d.py": '''
            def f():
                """Example:

                print("hello")
                """
                return 1
        '''})
        self.assertEqual(records, [])


# ───────────────────── defects the fixed rules uncovered ─────────────────────
class RegexBacktrackingTests(unittest.TestCase):
    """The Java/C# type-prefix regexes were exponential on a long line."""

    ADVERSARIAL = "public " + "a " * 40 + "!"

    def test_csharp_method_regex_is_linear(self) -> None:
        from ubs_core.csharp_detectors import security_randomness as cs

        started = time.monotonic()
        cs.METHOD_RE.search(self.ADVERSARIAL)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_java_func_regex_is_linear(self) -> None:
        from ubs_core.java_detectors import security_randomness as java

        started = time.monotonic()
        java.FUNC_RE.search(self.ADVERSARIAL)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_csharp_annotated_param_regex_is_linear(self) -> None:
        from ubs_core.csharp_detectors import header_injection as hi

        started = time.monotonic()
        hi.ANNOTATED_PARAM_RE.search("[FromQuery] " + "a " * 40 + "!")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_type_prefix_still_matches_generics(self) -> None:
        from ubs_core.csharp_detectors import security_randomness as cs

        for line, name in (
            ("    public static List<int, string> Foo(int a) {", "Foo"),
            ("    private Dictionary<string, List<int>> Bar() {", "Bar"),
            ("    int[] Baz(string s) =>", "Baz"),
        ):
            with self.subTest(line=line.strip()):
                match = cs.METHOD_RE.search(line)
                self.assertIsNotNone(match)
                self.assertEqual(match.group("name"), name)

    def test_no_detector_regex_mixes_space_into_a_repeated_token_class(self) -> None:
        """The bug class: a class containing ' ' repeated next to \\s under a +."""
        offenders = []
        for path in (HELPERS_DIR / "ubs_core").rglob("*.py"):
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"\[[^\]]* [^\]]*\]\+\\s\+\)\+", line):
                    offenders.append(f"{path.name}:{line_no}")
        self.assertEqual(offenders, [])


class AstGrepProbeTests(unittest.TestCase):
    def test_probe_is_bounded(self) -> None:
        from ubs_core import rust_scan

        started = time.monotonic()
        out = rust_scan._probe(sys.executable, "-c")
        self.assertLess(time.monotonic() - started, 10.0)
        self.assertIsInstance(out, str)

    def test_probe_swallows_a_missing_binary(self) -> None:
        from ubs_core import rust_scan

        self.assertEqual(rust_scan._probe("/nonexistent/ubs-probe-target", "--version"), "")

    def test_probe_closes_stdin(self) -> None:
        """A probe target that reads stdin must see EOF, not block."""
        from ubs_core import rust_scan

        script = "import sys; sys.stdout.write('eof' if sys.stdin.read() == '' else 'data')"
        with tempfile.TemporaryDirectory(prefix="ubs_probe_") as tmp:
            target = Path(tmp) / "probe.py"
            target.write_text(script, encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(target)], capture_output=True, text=True,
                stdin=subprocess.DEVNULL, timeout=10,
            )
        self.assertEqual(completed.stdout, "eof")


class FloatEqualityPrecisionTests(unittest.TestCase):
    def test_comments_strings_and_dependency_constraints_stay_clean(self) -> None:
        records = run_patterns("py.numeric.float-equality", {
            "notes.py": "# a == 1.0\n# b == 2.0\n# c == 3.0\n# d == 4.0\n"
                        "text = 'a == 1.0'\ntext = 'b == 2.0'\n"
                        "text = 'c == 3.0'\ntext = 'd == 4.0'\n",
            "uv.lock": 'requires-python = "==3.14.*"\n' * 4,
            "notes.toml": "# a == 1.0\n# b == 2.0\n# c == 3.0\n# d == 4.0\n",
        })
        self.assertEqual(records, [])

    def test_real_operators_keep_threshold_severity_and_locations(self) -> None:
        records = run_patterns("py.numeric.float-equality", {
            "operators.py": "a == 1.0  # a comment's apostrophe is not a string\n"
                            "b == 2.0\nc == 3.0\nd == 4.0\n"
                            "text = '== 5.0'  # e == 6.0\n",
        })
        self.assertEqual([record["line"] for record in records], [1, 2, 3, 4])
        self.assertTrue(all(record["severity"] == "warning" for record in records))
        self.assertEqual(run_patterns("py.numeric.float-equality", {
            "operators.py": "a == 1.0\nb == 2.0\nc == 3.0\n",
        }), [])

    def test_cython_operators_remain_visible(self) -> None:
        for suffix in ("pyx", "pxd", "pxi"):
            with self.subTest(suffix=suffix):
                records = run_patterns("py.numeric.float-equality", {
                    f"operators.{suffix}": "cdef double a\na == 1.0\nb == 2.0\nc == 3.0\nd == 4.0\n"
                                            "# e == 5.0\ntext = '== 6.0'\n",
                })
                self.assertEqual([record["line"] for record in records], [2, 3, 4, 5])
                self.assertTrue(all(record["severity"] == "warning" for record in records))

    def test_notebook_code_cells_keep_json_locations_and_ignore_prose(self) -> None:
        notebook = {
            "metadata": {"notes": "== 9.0"},
            "cells": [
                {"cell_type": "markdown", "source": ["a == 1.0\n", "b == 2.0\n"]},
                {"source": ["# a comment's == 7.0\n", "text = '== 8.0'\n",
                            "a == 1.0\n", "b == 2.0\n", "c == 3.0\n", "d == 4.0\n"],
                 "cell_type": "code", "outputs": [{"text": ["== 6.0\n"]}]},
                {"cell_type": "code", "source": "# a == 1.0\nb == 2.0\n", "outputs": []},
            ],
            "nbformat": 4, "nbformat_minor": 5,
        }
        for ascii_only in (True, False):
            with self.subTest(ascii_only=ascii_only):
                notebook["cells"][1]["source"][2] = "emoji = '😀'; a == 1.0\n"
                source = json.dumps(notebook, indent=2, ensure_ascii=ascii_only)
                records = run_patterns("py.numeric.float-equality", {"operators.ipynb": source})
                self.assertEqual([record["line"] for record in records], [17, 18, 19, 20, 33], (source, records))
                self.assertEqual(len(records), 5, records)
                self.assertTrue(all(record["severity"] == "warning" for record in records))
        clean = {"cells": [{"cell_type": "markdown", "source": ["== 1.0\n"] * 4},
                           {"cell_type": "code", "source": ["text = '== 1.0'\n"] * 4}],
                 "metadata": {"notes": "== 1.0"}, "nbformat": 4}
        self.assertEqual(run_patterns("py.numeric.float-equality", {
            "clean.ipynb": json.dumps(clean, indent=2),
        }), [])

    def test_real_cli_scans_notebook_operators_and_clean_controls(self) -> None:
        artifacts = REPO_ROOT / "test-suite" / "artifacts" / "python-notebook-operators"
        artifacts.mkdir(parents=True, exist_ok=True)
        for label, cell_type, code, expected in (
            ("operators", "code", [f"value == {index}.0\n" for index in range(1, 5)], 4),
            ("markdown", "markdown", [f"value == {index}.0\n" for index in range(1, 5)], 0),
            ("quoted", "code", ["text = '== 1.0'\n"] * 4, 0),
        ):
            case = f"python-notebook-{label}"
            started = time.perf_counter()
            print(f"[{case}] RUN", flush=True)
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix=f"{label}-", dir=artifacts) as tmp:
                root = Path(tmp)
                source = root / "input.ipynb"
                source.write_text(json.dumps({"cells": [{"cell_type": cell_type, "source": code}],
                                              "metadata": {}, "nbformat": 4, "nbformat_minor": 5}, indent=2))
                env = os.environ.copy()
                env.update(UBS_NO_CACHE="1", UBS_NO_AUTO_UPDATE="1")
                result = subprocess.run(
                    [str(REPO_ROOT / "ubs"), str(source), "--only=python", "--ci",
                     "--fail-on-warning", "--format=json"], cwd=root, env=env,
                    capture_output=True, text=True, timeout=60,
                )
                (artifacts / f"{label}-result.json").write_text(result.stdout)
                (artifacts / f"{label}-stderr.log").write_text(result.stderr)
                self.assertEqual(result.returncode, 1 if expected else 0, (result.stdout, result.stderr))
                try:
                    doc = json.loads(result.stdout)
                except json.JSONDecodeError as exc:
                    self.fail(f"Notebook CLI returned invalid JSON: {exc}; "
                              f"stdout={result.stdout!r}; stderr={result.stderr!r}")
                self.assertEqual(doc["status"], "ok", (result.stdout, result.stderr))
                self.assertEqual(doc["failed_modules"], [], (result.stdout, result.stderr))
                hits = [finding for finding in doc.get("findings", [])
                        if finding["rule_id"] == "py.numeric.float-equality"]
                self.assertEqual(len(hits), expected, (result.stdout, result.stderr))
                self.assertEqual(doc["totals"]["files"], 1, (result.stdout, result.stderr))
                self.assertEqual(doc["totals"]["critical"], 0, (result.stdout, result.stderr))
                self.assertEqual(doc["totals"]["warning"], expected, (result.stdout, result.stderr))
                print(f"[{case}] PASS ({time.perf_counter() - started:.3f}s)", flush=True)


class SourceLineTests(unittest.TestCase):
    def test_first_last_and_empty_lines_retain_exact_evidence(self) -> None:
        lines = ['first\tline', '', 'last\u2028line']
        self.assertEqual(source_line(lines, 1), lines[0])
        self.assertEqual(source_line(lines, 2), '')
        self.assertEqual(source_line(tuple(lines), 3), lines[2])

    def test_invalid_anchors_fail_instead_of_wrapping_or_guessing(self) -> None:
        for lines, line in ((['first', 'last'], 0), (['first', 'last'], -1),
                            (['first', 'last'], 3), ([], 1), (['first'], True),
                            (['first'], 1.0), (['first'], '1')):
            with self.subTest(lines=lines, line=line):
                with self.assertRaisesRegex(ValueError, 'analysis is incomplete'):
                    source_line(lines, line)


class NdjsonReaderTests(unittest.TestCase):
    def test_iterator_consumes_only_requested_records(self) -> None:
        consumed = []

        def lines():
            for index in range(3):
                consumed.append(index)
                yield json.dumps({"index": index}) + "\n"

        records = iter_ndjson_lines(lines(), "sink")
        self.assertEqual(consumed, [])
        self.assertEqual(next(records), {"index": 0})
        self.assertEqual(consumed, [0])
        self.assertEqual(list(records), [{"index": 1}, {"index": 2}])

    def test_malformed_line_is_skipped_not_fatal(self) -> None:
        stderr = io.StringIO()
        real, sys.stderr = sys.stderr, stderr
        try:
            records = parse_ndjson_lines(['{"a": 1}', "", "{truncated", '{"b": 2}'], "sink")
        finally:
            sys.stderr = real
        self.assertEqual(records, [{"a": 1}, {"b": 2}])
        self.assertIn("sink:3", stderr.getvalue())

    def test_non_object_records_are_dropped(self) -> None:
        self.assertEqual(parse_ndjson_lines(['{"a": 1}', "[1, 2]", "7"], "s"), [{"a": 1}])

    def test_missing_sink_yields_no_records(self) -> None:
        stderr = io.StringIO()
        real, sys.stderr = sys.stderr, stderr
        try:
            self.assertEqual(read_ndjson("/nonexistent/ubs-sink.ndjson"), [])
        finally:
            sys.stderr = real
        self.assertIn("cannot read NDJSON sink", stderr.getvalue())

    def test_round_trip(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_ndjson_") as tmp:
            sink = Path(tmp) / "s.ndjson"
            sink.write_text('{"rule": "r", "line": 1}\n\n{"rule": "s", "line": 2}\n', encoding="utf-8")
            self.assertEqual(
                read_ndjson(sink),
                [{"rule": "r", "line": 1}, {"rule": "s", "line": 2}],
            )

    def test_unicode_line_separators_inside_records_survive(self) -> None:
        record = {"message": "first\u0085second\u2028third\u2029fourth"}
        with tempfile.TemporaryDirectory(prefix="ubs_ndjson_") as tmp:
            sink = Path(tmp) / "s.ndjson"
            sink.write_text(json.dumps(record, ensure_ascii=False) + "\n", encoding="utf-8")
            self.assertEqual(read_ndjson(sink), [record])


class PythonPreviewOrderTests(unittest.TestCase):
    def test_real_scan_preview_sites_survive_input_order_and_parallelism(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ubs_python_previews_") as tmp:
            root = Path(tmp)
            paths = []
            for name in ("alpha", "bravo", "charlie", "delta", "echo"):
                source = root / f"{name}.py"
                source.write_text('handle = open("input.txt", encoding="utf-8")\n', encoding="utf-8")
                paths.append(source)
            baseline_report = None
            baseline_records = None
            env = os.environ.copy()
            env.update({"PYTHONPATH": str(HELPERS_DIR), "UBS_NO_CACHE": "1"})
            for index, (selected, jobs) in enumerate((
                (paths, 1),
                (list(reversed(paths)), 4),
                (paths[::2] + paths[1::2], 4),
            )):
                sink = root / f"findings-{index}.ndjson"
                report = root / f"report-{index}.json"
                proc = subprocess.run(
                    [sys.executable, "-m", "ubs_core.py_scan", "--files-from", "-",
                     "--sink", str(sink), "--json-out", str(report),
                     "--project-dir", str(root), "--project", str(root), "--jobs", str(jobs)],
                    input="\0".join(map(str, selected)) + "\0",
                    capture_output=True, text=True, env=env, cwd=REPO_ROOT, timeout=90,
                )
                self.assertIn(proc.returncode, (0, 1), proc.stderr)
                try:
                    doc = json.loads(report.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    self.fail(f"scanner did not emit valid JSON: {exc}; stderr={proc.stderr}")
                self.assertEqual(doc["status"], "ok")
                records = read_ndjson(sink)
                signatures = Counter(json.dumps(record, sort_keys=True) for record in records)
                findings = doc["findings"]
                open_finding = next(f for f in findings if f["rule_id"] == "py.io.open-missing-with")
                self.assertEqual(open_finding["count"], 5)
                self.assertEqual(open_finding["severity"], "warning")
                self.assertEqual(open_finding["samples"], [
                    {"file": str(path), "line": 1,
                     "code": 'handle = open("input.txt", encoding="utf-8")'}
                    for path in paths[:3]
                ])
                comparable = {
                    key: doc[key]
                    for key in ("files", "critical", "warning", "info", "findings", "report")
                }
                if baseline_report is None:
                    baseline_report, baseline_records = comparable, signatures
                else:
                    self.assertEqual(comparable, baseline_report)
                    self.assertEqual(signatures, baseline_records)

                # Duplicate evidence retains its multiplicity, while sample
                # choice is independent of its arrival order as well.
                from ubs_core.py_scan import _legacy_report

                duplicated = records + records
                forward = _legacy_report(duplicated, "test")
                backward = _legacy_report(list(reversed(duplicated)), "test")
                self.assertEqual(forward, backward)
                self.assertEqual(sum(f["count"] for f in forward["findings"]), len(duplicated))


class TrailingRootFlagTests(unittest.TestCase):
    """`--root` with no value used to raise IndexError from args[i + 1]."""

    def test_detectors_reject_a_valueless_root_flag(self) -> None:
        for module in ("ubs_core.rust_detectors.tls_indirect",
                       "ubs_core.rust_detectors.hardcoded_secrets"):
            with self.subTest(module=module):
                completed = subprocess.run(
                    [sys.executable, "-m", module, "--root"],
                    capture_output=True, text=True, cwd=str(HELPERS_DIR), timeout=60,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn("IndexError", completed.stderr)
                self.assertIn("--root requires a directory argument", completed.stderr)


class SelfScanShapeTests(unittest.TestCase):
    """The detectors that were rewritten must stay quiet on ubs's own sources."""

    def setUp(self) -> None:
        self.sources = [
            path
            for path in (REPO_ROOT / "modules" / "helpers").rglob("*.py")
            if "__pycache__" not in path.parts
        ]
        self.assertGreater(len(self.sources), 100)

    def test_open_handles_are_all_context_managed(self) -> None:
        self.assertEqual(list(io_open_checks.find(self.sources)), [])

    def test_index_arithmetic_stays_under_the_warning_tier(self) -> None:
        hits = list(index_arithmetic.find(self.sources))
        self.assertTrue(
            all(rule == "py.collections.index-arithmetic-info" for rule, *_ in hits),
            [h[1:3] for h in hits if h[0] != "py.collections.index-arithmetic-info"],
        )

    def test_division_stays_under_the_warning_tier(self) -> None:
        hits = list(division.find(self.sources))
        self.assertTrue(
            all(rule == "py.numeric.division" for rule, *_ in hits),
            [h[1:3] for h in hits if h[0] != "py.numeric.division"],
        )


# ──────────────────── sql-injection identifier sanitizers ────────────────────
class SqlIdentifierSanitizerTests(unittest.TestCase):
    """GH #133: a project-declared validator downgrades a checked identifier.

    A PostgreSQL identifier cannot be bound, so code targeting a
    runtime-configured table interpolates it after validating against a strict
    allowlist. The provenance tiers cannot express that on their own: an
    ``ast.Attribute`` is tainted no matter what ran before it. The downgrade is
    to Warning rather than silence, so a gate can tell a checked table name
    from a request parameter in an f-string without the finding disappearing.
    """

    SANITIZERS = "validate_sql_identifier,quote_ident,psycopg.sql.Identifier"

    CASES = {
        "validated.py": '''
            def validated(session, config):
                validate_sql_identifier(config.pg_table, "pg_table")
                return session.execute(text(f'SELECT 1 FROM "{config.pg_table}"'))
        ''',
        "unvalidated.py": '''
            def unvalidated(session, config):
                return session.execute(text(f'SELECT 1 FROM "{config.pg_table}"'))
        ''',
        "guard_after_sink.py": '''
            def guard_after_sink(session, config):
                rows = session.execute(text(f'SELECT 1 FROM "{config.pg_table}"'))
                validate_sql_identifier(config.pg_table, "pg_table")
                return rows
        ''',
        "other_expression.py": '''
            def other_expression(session, config):
                validate_sql_identifier(config.pg_schema, "pg_schema")
                return session.execute(text(f'SELECT 1 FROM "{config.pg_table}"'))
        ''',
        "sanitizer_return.py": '''
            def sanitizer_return(session, name):
                return session.execute(text(f'SELECT 1 FROM {quote_ident(name)}'))
        ''',
        "dotted_sanitizer.py": '''
            from psycopg import sql

            def dotted_sanitizer(session, name):
                return session.execute(text(f'SELECT 1 FROM {sql.Identifier(name)}'))
        ''',
        "validated_parameter.py": '''
            def validated_parameter(session, column):
                validate_sql_identifier(column, "column")
                return session.execute(text(f'SELECT "{column}" FROM t'))
        ''',
        "guard_in_nested_function.py": '''
            def guard_in_nested_function(session, config):
                def inner():
                    validate_sql_identifier(config.pg_table, "pg_table")
                inner()
                return session.execute(text(f'SELECT 1 FROM "{config.pg_table}"'))
        ''',
        "sink_in_nested_function.py": '''
            def sink_in_nested_function(session, config):
                validate_sql_identifier(config.pg_table, "pg_table")

                def inner():
                    return session.execute(text(f'SELECT 1 FROM "{config.pg_table}"'))
                return inner()
        ''',
        "sibling_value_not_blessed.py": '''
            def sibling_value_not_blessed(session, request):
                validate_sql_identifier(request.args["table"], "table")
                return session.execute(
                    text(f'SELECT * FROM t WHERE x = {request.args["value"]}')
                )
        ''',
        # ── function summaries: the reporter's real shape ──────────────────
        # The guard is a call to a helper, and the sanitizer runs one frame
        # down. v1 left this Critical because no sanitizer was called with
        # `config.pg_table` in this body.
        "wrapper_validates.py": '''
            class Writer:
                @classmethod
                def _validate_writeback_identifiers(cls, config, writeback_column):
                    validate_sql_identifier(config.pg_schema, "pg_schema")
                    validate_sql_identifier(config.pg_table, "pg_table")
                    validate_sql_identifier(writeback_column, "writeback_column")

                @classmethod
                def run(cls, session, config, writeback_column):
                    cls._validate_writeback_identifiers(config, writeback_column)
                    return session.execute(
                        text(f'SELECT "{writeback_column}" FROM "{config.pg_table}"')
                    )
        ''',
        # The line between a summary and prefix rooting. The wrapper validates
        # three named attributes of `config`; a fourth is not one of them and
        # must stay Critical. Prefix rooting would bless it.
        "wrapper_sibling_not_blessed.py": '''
            class Writer:
                @classmethod
                def _validate(cls, config):
                    validate_sql_identifier(config.pg_table, "pg_table")

                @classmethod
                def run(cls, session, config):
                    cls._validate(config)
                    return session.execute(
                        text(f'SELECT 1 FROM "{config.pg_unvalidated}"')
                    )
        ''',
        "wrapper_after_sink.py": '''
            class Writer:
                @classmethod
                def _validate(cls, config):
                    validate_sql_identifier(config.pg_table, "pg_table")

                @classmethod
                def run(cls, session, config):
                    rows = session.execute(text(f'SELECT 1 FROM "{config.pg_table}"'))
                    cls._validate(config)
                    return rows
        ''',
        # A wrapper that calls a wrapper. The summary fixpoint has to carry
        # the suffix through both frames.
        "wrapper_chain.py": '''
            def _inner(cfg):
                validate_sql_identifier(cfg.pg_table, "pg_table")

            def _outer(config):
                _inner(config)

            def run(session, config):
                _outer(config)
                return session.execute(text(f'SELECT 1 FROM "{config.pg_table}"'))
        ''',
        # Two methods share a name and only one validates. Nothing resolves
        # a call to a class here, so the summary keeps only what BOTH do —
        # which is nothing.
        "wrapper_name_collision.py": '''
            class Strict:
                def _check(self, config):
                    validate_sql_identifier(config.pg_table, "pg_table")

            class Loose:
                def _check(self, config):
                    return config

            def run(session, helper, config):
                helper._check(config)
                return session.execute(text(f'SELECT 1 FROM "{config.pg_table}"'))
        ''',
        # `*args` means no argument can be matched to a parameter name, so the
        # wrapper's summary cannot be applied to anything.
        "wrapper_star_args.py": '''
            def _validate(config):
                validate_sql_identifier(config.pg_table, "pg_table")

            def run(session, config, rest):
                _validate(*rest)
                return session.execute(text(f'SELECT 1 FROM "{config.pg_table}"'))
        ''',
    }

    def rules_for(self, sanitizers: str | None) -> dict[str, list[str]]:
        previous = os.environ.get(sql_injection.SANITIZER_ENV)
        if sanitizers is None:
            os.environ.pop(sql_injection.SANITIZER_ENV, None)
        else:
            os.environ[sql_injection.SANITIZER_ENV] = sanitizers
        try:
            hits = run_detector(sql_injection, self.CASES)
        finally:
            if previous is None:
                os.environ.pop(sql_injection.SANITIZER_ENV, None)
            else:
                os.environ[sql_injection.SANITIZER_ENV] = previous
        found: dict[str, list[str]] = {name: [] for name in self.CASES}
        for rule, path, *_ in hits:
            found[path.name].append(rule)
        return found

    def test_no_configuration_leaves_every_case_critical(self) -> None:
        # An empty list has to keep today's behaviour exactly, which is what
        # makes the feature safe to ship on by default.
        self.assertEqual(
            self.rules_for(None),
            {name: [sql_injection.RULE_CRITICAL] for name in self.CASES},
        )

    def test_declared_sanitizer_downgrades_only_what_it_guards(self) -> None:
        self.assertEqual(
            self.rules_for(self.SANITIZERS),
            {
                # Guarded before the sink, same expression: Warning, not silence.
                "validated.py": [sql_injection.RULE_WARNING],
                "validated_parameter.py": [sql_injection.RULE_WARNING],
                # Produced BY a sanitizer: safe by that function's contract.
                "sanitizer_return.py": [],
                "dotted_sanitizer.py": [],
                # Everything the guard does not reach stays Critical.
                "unvalidated.py": [sql_injection.RULE_CRITICAL],
                "guard_after_sink.py": [sql_injection.RULE_CRITICAL],
                "other_expression.py": [sql_injection.RULE_CRITICAL],
                "guard_in_nested_function.py": [sql_injection.RULE_CRITICAL],
                "sink_in_nested_function.py": [sql_injection.RULE_CRITICAL],
                "sibling_value_not_blessed.py": [sql_injection.RULE_CRITICAL],
                # A guard that happens inside a helper still counts, because
                # the helper's summary says which of its parameters reach a
                # sanitizer and as what.
                "wrapper_validates.py": [sql_injection.RULE_WARNING],
                "wrapper_chain.py": [sql_injection.RULE_WARNING],
                # …and only that. These are the four ways the summary must
                # decline, and the first is what separates it from prefix
                # rooting.
                "wrapper_sibling_not_blessed.py": [sql_injection.RULE_CRITICAL],
                "wrapper_after_sink.py": [sql_injection.RULE_CRITICAL],
                "wrapper_name_collision.py": [sql_injection.RULE_CRITICAL],
                "wrapper_star_args.py": [sql_injection.RULE_CRITICAL],
            },
        )

    def test_unrelated_sanitizer_names_change_nothing(self) -> None:
        # A configured name that the corpus never calls must not widen or
        # narrow anything, so a stale entry is inert rather than surprising.
        self.assertEqual(
            self.rules_for("some_other_validator"),
            {name: [sql_injection.RULE_CRITICAL] for name in self.CASES},
        )

    def test_configured_names_expand_to_their_dotted_suffixes(self) -> None:
        self.assertEqual(
            sql_injection.configured_sanitizers({"UBS_PY_SQL_SANITIZERS": "psycopg.sql.Identifier"}),
            frozenset({"psycopg.sql.Identifier", "sql.Identifier", "Identifier"}),
        )
        self.assertEqual(
            sql_injection.configured_sanitizers({"UBS_PY_SQL_SANITIZERS": " a , ,b "}),
            frozenset({"a", "b"}),
        )
        self.assertEqual(sql_injection.configured_sanitizers({}), frozenset())


class SqlSinkAdmissionTests(unittest.TestCase):
    """Irrelevant SQL flow does no transfer work; applicable flow stays intact."""

    SINKS = ('execute', 'executemany', 'executescript', 'exec_driver_sql', 'raw',
             'read_sql', 'read_sql_query', 'scalar', 'scalars', 'extra')

    @classmethod
    def setUpClass(cls):
        artifacts = REPO_ROOT / 'test-suite/artifacts'
        artifacts.mkdir(exist_ok=True)
        cls.artifacts = Path(tempfile.mkdtemp(prefix='sql-admission-', dir=artifacts))

    def source(self, name, contents):
        path = self.artifacts / name
        if isinstance(contents, bytes):
            path.write_bytes(contents)
        else:
            path.write_text(textwrap.dedent(contents), encoding='utf-8')
        return path

    def test_subprocess_chains_and_stdlib_need_no_sql_transfer_work(self):
        import argparse
        from test_taint_python_summaries import subprocess_chain

        paths = [self.source(f'chain-{count}.py', subprocess_chain(count))
                 for count in (50, 100)]
        paths.append(Path(argparse.__file__))
        for path in paths:
            with self.subTest(source=path.name):
                # A zero transfer budget still requires decoding, parsing, and
                # proving that no currently modeled SQL sink exists.
                self.assertEqual(list(sql_injection.find([path], max_steps=0)), [])

    def test_every_modeled_spelling_keeps_unsafe_and_parameterized_calls(self):
        for spelling in self.SINKS:
            for prefix in ('', 'cursor.'):
                call = prefix + spelling
                unsafe = ('where=[f"id = {user}"]' if spelling == 'extra'
                          else 'f"SELECT {user}"')
                safe = ('where=["id = %s"], params=[user]' if spelling == 'extra'
                        else '"SELECT %s", (user,)')
                for label, arguments in (('unsafe', unsafe), ('parameterized', safe)):
                    path = self.source(f'{spelling}-{prefix or "bare"}-{label}.py',
                                       f'def run(cursor, user):\n    {call}({arguments})\n')
                    with self.subTest(sink=call, case=label):
                        found = [(rule, line) for rule, _, line, _, _ in sql_injection.find([path])]
                        expected = [(sql_injection.RULE_CRITICAL, 2)] if label == 'unsafe' else []
                        self.assertEqual(found, expected)

    def test_sink_names_admit_full_flow_even_without_identified_arguments(self):
        for spelling in self.SINKS:
            path = self.source(f'empty-{spelling}.py', f'cursor.{spelling}()\n')
            with self.subTest(sink=spelling), self.assertRaisesRegex(
                    sql_injection.SQLFlowLimit, 'budget.*incomplete'):
                list(sql_injection.find([path], max_steps=0))

    def test_nested_and_definition_time_sinks_remain_visible(self):
        cases = {
            'nested': ('def outer(cursor, user):\n    def inner():\n'
                       '        cursor.execute(f"SELECT {user}")\n', 3),
            'default': ('def outer(cursor, user):\n'
                        '    def inner(query=cursor.execute(f"SELECT {user}")):\n'
                        '        return query\n', 2),
            'decorator': ('def outer(cursor, user):\n'
                          '    @cursor.execute(f"SELECT {user}")\n'
                          '    def inner():\n        return None\n', 2),
            'comprehension': ('def run(cursor, user):\n'
                              '    return [cursor.execute(f"SELECT {user}") for item in range(1)]\n', 2),
        }
        for name, (source, line) in cases.items():
            path = self.source(name + '.py', source)
            with self.subTest(case=name):
                self.assertEqual([(rule, found_line) for rule, _, found_line, _, _
                                  in sql_injection.find([path])],
                                 [(sql_injection.RULE_CRITICAL, line)])

    def test_configured_sanitizer_return_is_still_clean(self):
        from unittest.mock import patch

        path = self.source('sanitizer.py', 'def run(cursor, user):\n'
                           '    cursor.execute(f"SELECT {quote_ident(user)}")\n')
        with patch.dict(os.environ, {sql_injection.SANITIZER_ENV: ''}):
            self.assertEqual([(rule, line) for rule, _, line, _, _ in sql_injection.find([path])],
                             [(sql_injection.RULE_CRITICAL, 2)])
        with patch.dict(os.environ, {sql_injection.SANITIZER_ENV: 'quote_ident'}):
            self.assertEqual(list(sql_injection.find([path])), [])
            with self.assertRaisesRegex(sql_injection.SQLFlowLimit, 'budget.*incomplete'):
                list(sql_injection.find([path], max_steps=0))

    def test_read_decode_and_parse_failures_cannot_be_certified_clean(self):
        paths = [self.artifacts / 'missing.py',
                 self.source('invalid.py', 'def invalid(:\n    pass\n'),
                 self.source('undecodable.py', b'# coding: ascii\nvalue = "\xff"\n')]
        for path in paths:
            with self.subTest(source=path.name), self.assertRaisesRegex(
                    sql_injection.SQLFlowLimit, 'Cannot analyze.*incomplete'):
                list(sql_injection.find([path]))
        encoded = self.source('latin1.py', ('# coding: latin-1\ndef run(cursor, user):\n'
                              '    label = "caf\xe9"\n'
                              '    cursor.execute(f"SELECT {user}")\n').encode('latin-1'))
        self.assertEqual([(rule, line) for rule, _, line, _, _ in sql_injection.find([encoded])],
                         [(sql_injection.RULE_CRITICAL, 4)])

    @unittest.skipIf(sys.version_info < (3, 11), 'except* syntax requires Python 3.11')
    def test_exception_group_without_sql_is_complete_and_with_sql_is_incomplete(self):
        source = 'try:\n    work()\nexcept* ValueError:\n    recover()\n'
        path = self.source('exception-group-no-sql.py', source)
        self.assertEqual(list(sql_injection.find([path])), [])
        applicable = self.source('exception-group-sql.py',
                                 source + 'cursor.execute(f"SELECT {user}")\n')
        with self.assertRaisesRegex(sql_injection.SQLFlowLimit, r'except\*.*incomplete'):
            list(sql_injection.find([applicable]))

    def test_recursive_work_limit_remains_for_applicable_sql(self):
        source = ('def run(cursor, user):\n    queries = []\n'
                  '    def add(value, depth):\n        if depth:\n            add(value, depth - 1)\n'
                  '        else:\n            queries.append(value)\n'
                  '    add(f"SELECT {user}", 3)\n')
        path = self.source('recursive-no-sql.py', source)
        self.assertEqual(list(sql_injection.find([path], max_steps=20)), [])
        applicable = self.source('recursive-sql.py', source + '    cursor.execute(queries[-1])\n')
        with self.assertRaisesRegex(sql_injection.SQLFlowLimit, 'budget.*incomplete'):
            list(sql_injection.find([applicable], max_steps=20))


class LDAPReceiverIdentityTests(unittest.TestCase):
    def test_builtin_sets_are_not_directory_connections(self):
        cases = (
            ('private-set', 'def run(request):\n    verified = set()\n    verified.add(request.args["dn"])\n', []),
            ('literal-set', 'def run(request, set):\n    verified = {0}\n    verified.add(request.args["dn"])\n', []),
            ('directory-connection', 'def run(request, conn):\n    conn.add(request.args["dn"])\n', [2]),
            ('shadowed-factory', 'def run(request, set):\n    verified = set()\n    verified.add(request.args["dn"])\n', [3]),
            ('rebound-receiver', 'def run(request, conn):\n    verified = set()\n    verified = conn\n    verified.add(request.args["dn"])\n', [4]),
            ('conditional-rebinding', 'def run(request, conn):\n    verified = set()\n    if request.args:\n        verified = conn\n    verified.add(request.args["dn"])\n', [5]),
            ('conditional-parameter', 'def run(request, verified):\n    if request.args:\n        verified = set()\n    verified.add(request.args["dn"])\n', [4]),
            ('nonlocal-rebinding', 'def run(request, conn):\n    verified = set()\n    def replace():\n        nonlocal verified\n        verified = conn\n    replace()\n    verified.add(request.args["dn"])\n', [7]),
            ('reflected-rebinding', 'def run(request, conn):\n    verified = set()\n    locals()["verified"] = conn\n    verified.add(request.args["dn"])\n', [4]),
            ('pattern-shadowed-factory', 'def run(request, conn):\n    match conn:\n        case set:\n            verified = set()\n            verified.add(request.args["dn"])\n', [5]),
            ('dunder-shadowed-factory', 'import builtins\ndef run(request, conn):\n    builtins.__setattr__("set", lambda: conn)\n    verified = set()\n    verified.add(request.args["dn"])\n', [5]),
            ('function-globals-factory', 'def run(request, conn):\n    def helper(): pass\n    helper.__globals__["set"] = lambda: conn\n    verified = set()\n    verified.add(request.args["dn"])\n', [5]),
            ('closure-cell-receiver', 'def run(request, conn):\n    verified = {0}\n    def capture(): return verified\n    capture.__closure__[0].cell_contents = conn\n    verified.add(request.args["dn"])\n', [5]),
        )
        artifacts = REPO_ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix='ldap-receiver-', dir=artifacts))
        for name, source, expected in cases:
            with self.subTest(case=name):
                started = time.perf_counter()
                print(f'[{name}] RUN')
                path = work / f'{name}.py'
                path.write_text(source, encoding='utf-8')
                actual = [line for _, line, _, _ in ldap_injection.find([path])]
                (work / f'{name}.json').write_text(json.dumps({
                    'expected': expected, 'actual': actual,
                    'elapsed_seconds': time.perf_counter() - started,
                }, indent=2) + '\n', encoding='utf-8')
                self.assertEqual(actual, expected)
                print(f'[{name}] PASS ({time.perf_counter() - started:.3f}s)')


class LDAPFlowTests(unittest.TestCase):
    """Native LDAP operands and escape domains share ordinary Python flow."""

    @classmethod
    def setUpClass(cls):
        artifacts = REPO_ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(prefix='python-ldap-flow-', dir=artifacts))

    def check_cases(self, cases):
        for name, source in cases.items():
            with self.subTest(case=name):
                started = time.monotonic()
                print(f'[ldap-{name}] RUN', flush=True)
                source = textwrap.dedent(source).lstrip('\n')
                target = self.work / f'{name}.py'
                target.write_text(source, encoding='utf-8')
                expected = [line for line, text in enumerate(source.splitlines(), 1) if '# ldap-finding' in text]
                actual = list(ldap_injection.find([target]))
                (self.work / f'{name}.json').write_text(json.dumps({
                    'expected': expected, 'actual': [(str(p), line, col, message) for p, line, col, message in actual],
                    'elapsed_seconds': time.monotonic() - started,
                }, indent=2) + '\n', encoding='utf-8')
                self.assertEqual([line for _, line, _, _ in actual], expected, (source, actual))
                self.assertTrue(all(p == target and col > 0 for p, _, col, _ in actual), actual)
                print(f'[ldap-{name}] PASS ({time.monotonic() - started:.3f}s)', flush=True)

    def test_native_search_operand_positions_and_metadata(self):
        self.check_cases({
            'python-ldap-search': '''
                import ldap
                directory = ldap.initialize('ldap://directory.invalid')
                directory.search('dc=example', ldap.SCOPE_SUBTREE, request.args['filter'])  # ldap-finding
            ''',
            'python-ldap-scope-is-not-filter': '''
                import ldap
                directory = ldap.initialize('ldap://directory.invalid')
                directory.search('dc=example', request.args['scope'], '(uid=fixed)')
            ''',
            'python-ldap-search-base': '''
                import ldap
                directory = ldap.initialize('ldap://directory.invalid')
                directory.search_s(request.args['base'], ldap.SCOPE_SUBTREE, '(uid=fixed)')  # ldap-finding
            ''',
            'ldap3-search': '''
                from ldap3 import Connection
                directory = Connection('directory.invalid')
                directory.search('dc=example', request.args['filter'])  # ldap-finding
            ''',
            'ldap3-metadata': '''
                from ldap3 import Connection
                directory = Connection('directory.invalid')
                directory.search('dc=example', '(uid=fixed)', attributes=request.args['attributes'])
            ''',
            'native-keyword-slots': '''
                import ldap
                from ldap3 import Connection
                first = ldap.initialize('ldap://directory.invalid')
                second = Connection('directory.invalid')
                first.search(base='dc=example', scope=ldap.SCOPE_SUBTREE, filterstr=request.args['filter'])  # ldap-finding
                second.search(search_base=request.args['base'], search_filter='(uid=fixed)')  # ldap-finding
            ''',
            'ldap3-paged-search-extension': '''
                from ldap3 import Connection
                directory = Connection('directory.invalid')
                directory.extend.standard.paged_search('dc=example', request.args['filter'])  # ldap-finding
            ''',
            'ldap3-saved-paged-search-extension': '''
                from ldap3 import Connection
                directory = Connection('directory.invalid')
                standard = directory.extend.standard
                paged = standard.paged_search
                paged(request.args['base'], '(uid=fixed)')  # ldap-finding
            ''',
        })

    def test_native_unbound_class_operands(self):
        self.check_cases({
            'unbound-ldap3-search': '''
                from ldap3 import Connection
                directory = Connection('directory.invalid')
                Connection.search(directory, 'dc=example', request.args['filter'])  # ldap-finding
                directory.search('dc=example', request.args['next'])  # ldap-finding
            ''',
            'saved-unbound-search-before-class-rebind': '''
                from ldap3 import Connection
                directory = Connection('directory.invalid')
                search = Connection.search
                Connection = external_factory
                search(directory, 'dc=example', request.args['filter'])  # ldap-finding
            ''',
            'unbound-python-ldap-search': '''
                from ldap.ldapobject import LDAPObject
                directory = LDAPObject('ldap://directory.invalid')
                LDAPObject.search(directory, 'dc=example', 2, request.args['filter'])  # ldap-finding
                LDAPObject.search(directory, 'dc=example', request.args['scope'], '(uid=fixed)')
            ''',
            'unbound-dn-positions': '''
                from ldap3 import Connection
                directory = Connection('directory.invalid')
                Connection.add(directory, request.args['dn'])  # ldap-finding
                Connection.modify_dn(directory, 'cn=old,dc=example', request.args['rdn'])  # ldap-finding
                Connection.modify_dn(directory, 'cn=old,dc=example', 'cn=new', True, request.args['parent'])  # ldap-finding
                Connection.modify_dn(directory, 'cn=old,dc=example', 'cn=new', request.args['delete_flag'])
            ''',
            'unbound-keyword-self': '''
                from ldap3 import Connection
                from ldap.ldapobject import LDAPObject
                directory = Connection('directory.invalid')
                Connection.search(self=directory, search_base='dc=example', search_filter=request.args['filter'])  # ldap-finding
                Connection.add(self=directory, dn=request.args['dn'])  # ldap-finding
                legacy = LDAPObject('ldap://directory.invalid')
                LDAPObject.search(self=legacy, base='dc=example', scope=2, filterstr=request.args['filter'])  # ldap-finding
            ''',
            'unbound-expanded-positions': '''
                from ldap3 import Connection
                directory = Connection('directory.invalid')
                Connection.search(*(directory, 'dc=example', request.args['filter']))  # ldap-finding
                Connection.search(*(directory, 'dc=example', '(uid=fixed)'), attributes=request.args['attributes'])
            ''',
            'unbound-domain-and-metadata-controls': '''
                from ldap3 import Connection
                from ldap3.utils.conv import escape_filter_chars
                directory = Connection('directory.invalid')
                Connection.search(directory, 'dc=example', escape_filter_chars(request.args['filter']))
                Connection.search(directory, 'dc=example', '(uid=fixed)', attributes=request.args['attributes'])
                Connection.add(directory, 'cn=fixed,dc=example', attributes={'sn': request.args['surname']})
                Connection.search(directory, request.args['base'], escape_filter_chars(request.args['filter']))  # ldap-finding
            ''',
            'unbound-local-class-lookalike': '''
                class Connection:
                    def search(self, base, value): return value
                Connection.search(object(), 'fixed', request.args['filter'])
            ''',
        })

    @unittest.skipUnless(os.environ.get('UBS_LDAP_NATIVE') == '1', 'set UBS_LDAP_NATIVE=1 with ldap3 installed')
    def test_native_unbound_class_runtime(self):
        from ldap3 import Connection, Server, MOCK_SYNC, NONE
        connection = Connection(Server('offline.invalid', get_info=NONE), client_strategy=MOCK_SYNC)
        connection.strategy.add_entry('cn=known,dc=example',
                                      {'objectClass': ['person'], 'cn': ['known'], 'sn': ['known']})
        self.assertTrue(connection.bind())
        self.assertTrue(Connection.search(connection, 'dc=example', '(cn=known)'))
        self.assertEqual(len(connection.entries), 1)
        saved = Connection.search
        self.assertTrue(saved(self=connection, search_base='dc=example', search_filter='(cn=known)'))
        self.assertEqual(len(connection.entries), 1)
        self.assertTrue(Connection.add(connection, 'cn=other,dc=example', object_class='person',
                                       attributes={'sn': 'other'}))
        self.assertTrue(connection.search('cn=other,dc=example', '(objectClass=person)'))
        self.assertEqual(len(connection.entries), 1)
        self.assertTrue(connection.unbind())

    def test_native_dn_operands_include_rename_targets(self):
        self.check_cases({
            'ldap3-relative-dn': '''
                from ldap3 import Connection
                directory = Connection('directory.invalid')
                directory.modify_dn('cn=fixed,dc=example', request.args['relative'])  # ldap-finding
                directory.modify_dn('cn=fixed,dc=example', 'cn=other', new_superior=request.args['parent'])  # ldap-finding
            ''',
            'python-ldap-new-rdn-and-superior': '''
                import ldap
                directory = ldap.initialize('ldap://directory.invalid')
                directory.rename_s('cn=fixed,dc=example', request.args['rdn'])  # ldap-finding
                directory.rename_s('cn=fixed,dc=example', 'cn=other', request.args['parent'])  # ldap-finding
            ''',
            'dn-metadata-clean': '''
                from ldap3 import Connection
                directory = Connection('directory.invalid')
                directory.add('cn=fixed,dc=example', attributes={'description': request.args['description']})
                directory.modify_dn('cn=fixed,dc=example', 'cn=other', delete_old_dn=request.args['flag'])
            ''',
        })

    def test_helpers_and_call_contexts_preserve_provenance(self):
        self.check_cases({
            'helper-argument': '''
                def lookup(value):
                    conn.search('dc=example', value)  # ldap-finding
                lookup(request.args['filter'])
            ''',
            'helper-return': '''
                def build(value): return '(uid=' + value + ')'
                conn.search('dc=example', build(request.args['name']))  # ldap-finding
            ''',
            'unsafe-then-safe': '''
                def identity(value): return value
                conn.search('dc=example', identity(request.args['filter']))  # ldap-finding
                conn.search('dc=example', identity('(uid=fixed)'))
            ''',
            'safe-then-unsafe': '''
                def identity(value): return value
                conn.search('dc=example', identity('(uid=fixed)'))
                conn.search('dc=example', identity(request.args['filter']))  # ldap-finding
            ''',
            'fixed-helper-result': '''
                def fixed(value): return '(uid=fixed)'
                conn.search('dc=example', fixed(request.args['filter']))
            ''',
        })

    def test_branches_overwrites_and_abrupt_paths(self):
        self.check_cases({
            'conditional-cleanup': '''
                value = request.args['filter']
                if enabled: value = '(uid=fixed)'
                conn.search('dc=example', value)  # ldap-finding
            ''',
            'strong-cleanup': '''
                value = request.args['filter']
                value = '(uid=fixed)'
                conn.search('dc=example', value)
            ''',
            'later-source': '''
                value = '(uid=fixed)'
                conn.search('dc=example', value)
                value = request.args['filter']
            ''',
            'dead-sink': '''
                def handle(request):
                    return 'done'
                    conn.search('dc=example', request.args['filter'])
            ''',
        })

    def test_aliases_saved_methods_and_native_factories(self):
        self.check_cases({
            'module-constructor-alias': '''
                import ldap as directory_api
                make = directory_api.initialize
                client = make('ldap://directory.invalid')
                search = client.search
                search('dc=example', 2, request.args['filter'])  # ldap-finding
            ''',
            'captured-before-rebind': '''
                from ldap3 import Connection as Connect
                client = Connect('directory.invalid')
                search = client.search
                client = set()
                search('dc=example', request.args['filter'])  # ldap-finding
            ''',
            'selected-native-factory': '''
                from ldap3 import Connection
                def connect(): return Connection('directory.invalid')
                client = connect()
                client.search('dc=example', request.args['filter'])  # ldap-finding
            ''',
            'saved-method-helper': '''
                from ldap3 import Connection
                client = Connection('directory.invalid')
                def invoke(search, value): search('dc=example', value)  # ldap-finding
                invoke(client.search, request.args['filter'])
            ''',
        })

    def test_filter_and_dn_sanitizers_are_separate(self):
        self.check_cases({
            'native-filter-alias': '''
                from ldap.filter import escape_filter_chars as escape
                conn.search('dc=example', '(uid=' + escape(request.args['name']) + ')')
            ''',
            'native-dn-alias': '''
                from ldap.dn import escape_dn_chars as escape
                conn.add('cn=' + escape(request.args['name']) + ',dc=example')
            ''',
            'dn-escape-in-filter': '''
                from ldap.dn import escape_dn_chars
                conn.search('dc=example', '(uid=' + escape_dn_chars(request.args['name']) + ')')  # ldap-finding
            ''',
            'filter-escape-in-dn': '''
                from ldap.filter import escape_filter_chars
                conn.add('cn=' + escape_filter_chars(request.args['name']) + ',dc=example')  # ldap-finding
            ''',
            'ldap3-filter-and-dn': '''
                from ldap3.utils.conv import escape_filter_chars as filter_value
                from ldap3.utils.dn import escape_rdn as dn_value
                conn.search('dc=example', '(uid=' + filter_value(request.args['name']) + ')')
                conn.add('cn=' + dn_value(request.args['name']) + ',dc=example')
                conn.search('dc=example', '(uid=' + dn_value(request.args['name']) + ')')  # ldap-finding
            ''',
        })

    def test_sanitizer_identity_and_helper_bodies(self):
        self.check_cases({
            'reassuring-name': '''
                def sanitize_ldap_filter_value(value): return value
                conn.search('dc=example', sanitize_ldap_filter_value(request.args['filter']))  # ldap-finding
            ''',
            'local-shadow': '''
                from ldap.filter import escape_filter_chars
                escape_filter_chars = lambda value: value
                conn.search('dc=example', escape_filter_chars(request.args['filter']))  # ldap-finding
            ''',
            'foreign-lookalike': '''
                from unrelated import escape_filter_chars
                conn.search('dc=example', escape_filter_chars(request.args['filter']))  # ldap-finding
            ''',
            'relative-lookalike': '''
                from .ldap.filter import escape_filter_chars
                conn.search('dc=example', escape_filter_chars(request.args['filter']))  # ldap-finding
            ''',
            'body-proven-helper': '''
                from ldap.filter import escape_filter_chars as escaped
                def prepare(value): return escaped(value)
                conn.search('dc=example', '(uid=' + prepare(request.args['name']) + ')')
            ''',
            'unknown-transform-revokes-proof': '''
                from ldap.filter import escape_filter_chars
                def restore(value): return external_decode(value)
                conn.search('dc=example', restore(escape_filter_chars(request.args['filter'])))  # ldap-finding
            ''',
        })

    def test_namespace_writes_and_captured_sanitizers(self):
        self.check_cases({
            'changed-module': '''
                import ldap.filter as escaping
                escaping.escape_filter_chars = lambda value: value
                conn.search('dc=example', escaping.escape_filter_chars(request.args['filter']))  # ldap-finding
            ''',
            'captured-before-module-write': '''
                import ldap.filter as escaping
                encode = escaping.escape_filter_chars
                escaping.escape_filter_chars = lambda value: value
                conn.search('dc=example', encode(request.args['filter']))
            ''',
            'helper-module-write': '''
                import ldap.filter as escaping
                def replace(module): module.escape_filter_chars = lambda value: value
                replace(escaping)
                conn.search('dc=example', escaping.escape_filter_chars(request.args['filter']))  # ldap-finding
            ''',
        })

    def test_builtin_receiver_identity_and_rebinding(self):
        self.check_cases({
            'global-set-alias': '''
                items = set()
                alias = items
                alias.add(request.args['dn'])
            ''',
            'helper-owned-set': '''
                def add(items, value): items.add(value)
                items = set()
                add(items, request.args['dn'])
            ''',
            'owned-instance-field': '''
                class Index:
                    def __init__(self): self.parameters = set()
                    def collect(self, request): self.parameters.add(request.parameter)
            ''',
            'field-rebound-to-directory': '''
                class Index:
                    def __init__(self): self.parameters = set()
                    def collect(self, request, connection):
                        self.parameters = connection
                        self.parameters.add(request.parameter)  # ldap-finding
            ''',
            'conditional-native-or-set': '''
                from ldap3 import Connection
                client = set() if enabled else Connection('directory.invalid')
                client.add(request.args['dn'])  # ldap-finding
            ''',
            'owned-field-receiver-reassigned': '''
                class Index:
                    def __init__(self): self.parameters = set()
                    def collect(self, request, replacement):
                        self = replacement
                        self.parameters.add(request.parameter)  # ldap-finding
            ''',
            'owned-field-escaped': '''
                class Index:
                    def __init__(self): self.parameters = set()
                    def collect(self, request):
                        mutate(self)
                        self.parameters.add(request.parameter)  # ldap-finding
            ''',
            'owned-field-reflected-write': '''
                class Index:
                    def __init__(self): self.parameters = set()
                    def collect(self, request, directory):
                        object.__setattr__(self, 'parameters', directory)
                        self.parameters.add(request.parameter)  # ldap-finding
            ''',
            'unrelated-fixed-field-write': '''
                class Index:
                    def __init__(self): self.parameters = set()
                    def collect(self, request):
                        self.parameters.add(request.parameter)
                class Counter:
                    def count(self): object.__setattr__(self, 'counted', True)
            ''',
            'unbound-instance-field-receiver': '''
                import ldap3
                from types import SimpleNamespace
                class Holder:
                    def __init__(self): self.tokens = set()
                    def use(self, request): self.tokens.add(request.args['dn'])  # ldap-finding
                def handle(request):
                    other = SimpleNamespace(tokens=ldap3.Connection('directory.invalid'))
                    Holder.use(other, request)
            ''',
            'saved-unbound-instance-field-receiver': '''
                import ldap3
                from types import SimpleNamespace
                class Holder:
                    def __init__(self): self.tokens = set()
                    def use(self, request): self.tokens.add(request.args['dn'])  # ldap-finding
                saved = Holder.use
                def handle(request):
                    other = SimpleNamespace(tokens=ldap3.Connection('directory.invalid'))
                    saved(other, request)
            ''',
        })

    def test_set_identity_uses_lexical_bindings_and_real_reflection(self):
        self.check_cases({
            'readonly-builtin-inventory': '''
                import builtins
                inventory = {name: value for name, value in vars(builtins).items()}
                def collect(request):
                    values = set()
                    values.add(request.args['dn'])
            ''',
            'unrelated-set-parameter': '''
                def custom(set): return set()
                def collect(request):
                    values = set()
                    values.add(request.args['dn'])
            ''',
            'finite-reflective-metadata-fields': '''
                def configure(target):
                    for field in ('metadata', 'options'):
                        setattr(target, field, {})
                def collect(request):
                    values = set()
                    values.add(request.args['dn'])
            ''',
            'finite-reflection-includes-set': '''
                import builtins
                for field in ('set', 'metadata'):
                    setattr(builtins, field, opaque_factory)
                values = set()
                values.add(request.args['dn'])  # ldap-finding
            ''',
            'reflective-field-name-reassigned': '''
                import builtins
                for field in ('metadata', 'options'):
                    field = request.args['field']
                    setattr(builtins, field, opaque_factory)
                values = set()
                values.add(request.args['dn'])  # ldap-finding
            ''',
            'native-static-and-class-methods': '''
                class Collector:
                    def __init__(self): self.values = set()
                    @staticmethod
                    def identity(value): return value
                    @classmethod
                    def make(cls): return cls()
                    def collect(self, request): self.values.add(request.args['dn'])
            ''',
            'ordinary-cell-contents-method': '''
                class Collector:
                    def __init__(self): self.values = set()
                    def cell_contents(self, value): return value
                    def collect(self, request):
                        self.cell_contents('fixed')
                        self.values.add(request.args['dn'])
            ''',
            'contained-instance-escapes-before-use': '''
                class Collector:
                    def __init__(self, request):
                        self.values = set()
                        self.peers = (self,)
                        mutate(self.peers)
                        self.values.add(request.args['dn'])  # ldap-finding
            ''',
            'fresh-field-overwritten-by-helper': '''
                def rebind(owner, directory): owner.values = directory
                class Collector:
                    def __init__(self, request, directory):
                        self.values = set()
                        rebind(self, directory)
                        self.values.add(request.args['dn'])  # ldap-finding
            ''',
            'older-escaped-alias-mutated-after-assignment': '''
                class Collector:
                    def __init__(self, request):
                        remember(self)
                        self.values = set()
                        mutate_remembered()
                        self.values.add(request.args['dn'])  # ldap-finding
            ''',
            'transitive-instance-method-escape': '''
                class Collector:
                    def __init__(self, request):
                        self.values = set()
                        self.change()
                        self.values.add(request.args['dn'])  # ldap-finding
                    def change(self): mutate(self)
            ''',
            'fresh-field-escape-on-assignment-line': '''
                class Collector:
                    def __init__(self, request):
                        self.values = set(); mutate(self)
                        self.values.add(request.args['dn'])  # ldap-finding
            ''',
            'shadowed-vars-inventory': '''
                import builtins
                def collect(request, vars):
                    inventory = dict(vars(builtins).items())
                    values = set()
                    values.add(request.args['dn'])  # ldap-finding
            ''',
            'shadowed-builtins-inventory': '''
                import builtins
                def collect(request, builtins):
                    inventory = dict(vars(builtins).items())
                    values = set()
                    values.add(request.args['dn'])  # ldap-finding
            ''',
            'shadowed-staticmethod-decorator': '''
                def staticmethod(callback): return external_decorator(callback)
                class Collector:
                    def __init__(self): self.values = set()
                    @staticmethod
                    def identity(value): return value
                    def collect(self, request): self.values.add(request.args['dn'])  # ldap-finding
            ''',
            'mutated-native-staticmethod': '''
                import builtins
                builtins.staticmethod = external_decorator
                class Collector:
                    def __init__(self): self.values = set()
                    @staticmethod
                    def identity(value): return value
                    def collect(self, request): self.values.add(request.args['dn'])  # ldap-finding
            ''',
            'mutated-native-vars': '''
                import builtins
                builtins.vars = opaque_inventory
                inventory = dict(vars(builtins).items())
                values = set()
                values.add(request.args['dn'])  # ldap-finding
            ''',
            'escaped-cell-contents': '''
                def collect(request):
                    values = set()
                    def capture(): return values
                    external(capture.__closure__[0])
                    values.add(request.args['dn'])  # ldap-finding
            ''',
        })

    @unittest.skipUnless(os.environ.get('UBS_PY_LDAP_CONSTRUCTOR_PRECISION') == '1',
                         'open constructor precision cohort; preserve clean expectations until alias proof is complete')
    def test_constructor_precision_open_cohort(self):
        """Known clean controls remain open, not redefined as unsafe success.

        Earlier escaped aliases and transitive method effects currently rule
        out the general constructor-field proof. These original controls must
        remain clean targets for a future sound lifetime model.
        """
        self.check_cases({
            'fresh-constructor-field-after-self-reference': '''
                class Collector:
                    def __init__(self, request):
                        self.peers = (self,)
                        self.values = set()
                        self.values.add(request.args['dn'])
            ''',
            'fresh-field-before-later-external-writer': '''
                class Collector:
                    def __init__(self, request):
                        self.values = set()
                        self.peers = (self,)
                        self.values.add(request.args['dn'])
                    def collect(self, request): self.values.add(request.args['dn'])  # ldap-finding
                def rebind(owner, directory): owner.values = directory
            ''',
            'fresh-field-before-same-line-escape': '''
                class Collector:
                    def __init__(self, request):
                        mutate(self); self.values = set()
                        self.values.add(request.args['dn'])
            ''',
        })

    def test_native_sources_and_query_formatting(self):
        self.check_cases({
            'environment-alias': '''
                from os import getenv as setting
                conn.search('dc=example', setting('LDAP_FILTER'))  # ldap-finding
            ''',
            'stdin-through-helper': '''
                import sys
                def read(): return sys.stdin.readline()
                conn.search('dc=example', read())  # ldap-finding
            ''',
            'filter-format': '''
                from ldap.filter import filter_format
                conn.search('dc=example', filter_format('(uid=%s)', [request.args['name']]))
            ''',
            'tainted-filter-template': '''
                from ldap.filter import filter_format
                conn.search('dc=example', filter_format(request.args['template'], ['fixed']))  # ldap-finding
            ''',
            'later-source-in-composition': '''
                from ldap.filter import escape_filter_chars
                safe = escape_filter_chars(request.args['name'])
                conn.search('dc=example', '(uid=' + safe + request.args['suffix'] + ')')  # ldap-finding
            ''',
        })

    def test_suppression_owns_sink_not_source(self):
        self.check_cases({
            'source-marker': '''
                value = request.args['filter']  # ubs:ignore[py.security.ldap-injection]
                conn.search('dc=example', value)  # ldap-finding
            ''',
            'sink-marker': '''
                conn.search('dc=example', request.args['filter'])  # ubs:ignore[py.security.ldap-injection]
            ''',
            'other-rule': '''
                conn.search('dc=example', request.args['filter'])  # ubs:ignore[py.security.header-injection] # ldap-finding
            ''',
        })

    @unittest.skipUnless(os.environ.get('UBS_LDAP_NATIVE') == '1', 'set UBS_LDAP_NATIVE=1 with ldap3 installed')
    def test_native_ldap3_escape_domains_and_directory_queries(self):
        from ldap3 import Connection, Server, MOCK_SYNC, NONE
        from ldap3.utils.conv import escape_filter_chars
        from ldap3.utils.dn import escape_rdn, parse_dn
        connection = Connection(Server('offline.invalid', get_info=NONE), client_strategy=MOCK_SYNC)
        connection.strategy.add_entry('dc=example', {'objectClass': ['domain'], 'dc': ['example']})
        for name in ('alice', 'bob'):
            connection.strategy.add_entry(f'cn={name},dc=example',
                                          {'objectClass': ['person'], 'cn': [name], 'sn': [name], 'uid': [name]})
        self.assertTrue(connection.bind())
        saved_search = connection.search
        wildcard = '*'
        self.assertTrue(saved_search('dc=example', '(uid=' + escape_rdn(wildcard) + ')', attributes=['uid']))
        self.assertEqual(len(connection.entries), 2)
        saved_search('dc=example', '(uid=' + escape_filter_chars(wildcard) + ')', attributes=['uid'])
        self.assertEqual(len(connection.entries), 0)
        injected_dn = 'first,ou=admins'
        self.assertEqual(len(parse_dn('cn=' + escape_filter_chars(injected_dn) + ',dc=example')), 3)
        self.assertEqual(len(parse_dn('cn=' + escape_rdn(injected_dn) + ',dc=example')), 2)
        from types import SimpleNamespace
        from unittest import mock
        class Holder:
            def __init__(self): self.tokens = set()
            def use(self, request):
                return self.tokens.add(request.args['dn'], object_class='person', attributes={'sn': 'unbound'})
        saved_unbound = Holder.use
        native_receiver = SimpleNamespace(tokens=connection)
        user_request = SimpleNamespace(args={'dn': 'cn=unbound,dc=example'})
        with mock.patch.object(connection, 'add', wraps=connection.add) as actual_add:
            self.assertTrue(saved_unbound(native_receiver, user_request))
            actual_add.assert_called_once_with('cn=unbound,dc=example', object_class='person',
                                               attributes={'sn': 'unbound'})
        self.assertTrue(connection.search('cn=unbound,dc=example', '(objectClass=person)'))
        self.assertEqual(len(connection.entries), 1)
        self.assertTrue(connection.unbind())

    def test_partial_files_retain_independent_findings(self):
        from unittest import mock
        malformed, safe, unsafe = [self.work / name for name in ('malformed.py', 'safe.py', 'unsafe.py')]
        malformed.write_text('conn.search( = request.args["filter"]\n', encoding='utf-8')
        safe.write_text('conn.search("dc=example", "(uid=fixed)")\n', encoding='utf-8')
        unsafe.write_text('def lookup(value): conn.search("dc=example", value)\n'
                          'lookup(request.args["filter"])\n', encoding='utf-8')
        for paths in ([malformed, safe, unsafe], [unsafe, safe, malformed]):
            findings = []
            with self.assertRaisesRegex(RuntimeError, 'incomplete LDAP analysis.*SyntaxError'):
                findings.extend(ldap_injection.find(paths))
            self.assertEqual([(path, line, col) for path, line, col, _ in findings], [(unsafe, 1, 20)])
        limited = self.work / 'scope-limited.py'
        limited.write_text('conn.search("dc=example", request.args["first"])\n'
                           'def expensive(value):\n' + '    value = str(value)\n' * 100 +
                           '    return value\n'
                           'conn.search("dc=example", request.args["last"])\n', encoding='utf-8')
        findings = []
        with mock.patch.dict(os.environ, {'UBS_PYTHON_FLOW_SCOPE_STEPS': '200'}), \
                self.assertRaisesRegex(ldap_injection.LDAPAnalysisLimit, 'work limit') as raised:
            findings.extend(ldap_injection.find([limited]))
        self.assertEqual([line for _, line, _, _ in findings], [1, 104])
        self.assertTrue(raised.exception.components)

    def test_native_receiver_mutation_and_escape_are_explicitly_partial(self):
        cases = {
            'receiver-method-write': 'directory.search = external_search\n',
            'factory-method-write': 'Connection.search = external_search\n',
            'receiver-escape': 'configure(directory)\ndirectory.search("dc=example", request.args["later"])\n',
            'helper-receiver-write': 'def replace(value): value.search = external_search\nreplace(directory)\n',
        }
        for label, operation in cases.items():
            with self.subTest(case=label):
                target = self.work / f'{label}.py'
                target.write_text('from ldap3 import Connection\n'
                                  'directory = Connection("directory.invalid")\n'
                                  'directory.search("dc=example", request.args["filter"])\n' + operation,
                                  encoding='utf-8')
                findings = []
                with self.assertRaisesRegex(ldap_injection.LDAPAnalysisLimit, 'native LDAP receiver'):
                    findings.extend(ldap_injection.find([target]))
                self.assertEqual([line for _, line, _, _ in findings], [3])


class HeaderInjectionFlowTests(unittest.TestCase):
    """Header decisions must follow actual values, callees and control flow."""

    @classmethod
    def setUpClass(cls):
        artifacts = REPO_ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(prefix='python-header-flow-', dir=artifacts))

    def check_cases(self, cases):
        for name, source in cases.items():
            with self.subTest(case=name):
                source = textwrap.dedent(source).lstrip('\n')
                path = self.work / f'{name}.py'
                path.write_text(source, encoding='utf-8')
                expected = [index for index, line in enumerate(source.splitlines(), 1)
                            if '# header-finding' in line]
                actual = list(header_injection.find([path]))
                self.assertEqual([hit[1] for hit in actual], expected)
                self.assertTrue(all(hit[0] == path and hit[2] > 0 for hit in actual))

    def test_helper_bodies_scope_and_overwrites(self):
        self.check_cases({
            'fake-sanitizer': '''
                def sanitize_header_value(value): return value
                response.headers['X'] = sanitize_header_value(request.args['x'])  # header-finding
            ''',
            'safe-imported-wrapper': '''
                from urllib.parse import quote as encode
                def prepare(value): return encode(value, safe='')
                response.headers['X'] = prepare(request.args['x'])
            ''',
            'identity-retains-caller-proof': '''
                from urllib.parse import quote
                def identity(value): return value
                response.headers['X'] = identity(quote(request.args['x']))
            ''',
            'helper-sink': '''
                def emit(value): response.headers['X'] = value  # header-finding
                emit(request.args['x'])
            ''',
            'overwritten-source': '''
                value = request.args['x']
                value = 'fixed'
                response.headers['X'] = value
            ''',
            'conditional-overwrite': '''
                value = request.args['x']
                if enabled: value = 'fixed'
                response.headers['X'] = value  # header-finding
            ''',
            'unrelated-same-name': '''
                from urllib.parse import quote
                def first(value):
                    def quote(value): return value
                    return quote(value)
                def second(value): return quote(value)
                response.headers['X'] = first(request.args['x'])  # header-finding
                response.headers['Y'] = second(request.args['x'])
            ''',
        })

    def test_both_control_characters_require_dominating_proof(self):
        self.check_cases({
            'reject-both': r'''
                def checked(value):
                    if '\r' in value or '\n' in value: raise ValueError('header')
                    return value
                response.headers['X'] = checked(request.args['x'])
            ''',
            'reject-only-cr': r'''
                def checked(value):
                    if '\r' in value: raise ValueError('header')
                    return value
                response.headers['X'] = checked(request.args['x'])  # header-finding
            ''',
            'reject-pair-only': r'''
                value = request.args['x']
                if '\r' in value and '\n' in value: raise ValueError('header')
                response.headers['X'] = value  # header-finding
            ''',
            'other-value-guard': r'''
                value = request.args['x']
                other = request.args['y']
                if '\r' in other or '\n' in other: raise ValueError('header')
                response.headers['X'] = value  # header-finding
            ''',
            'post-sink-guard': r'''
                value = request.args['x']
                response.headers['X'] = value  # header-finding
                if '\r' in value or '\n' in value: raise ValueError('header')
            ''',
            'guarded-reassignment': r'''
                value = request.args['x']
                if '\r' in value or '\n' in value: raise ValueError('header')
                value = request.args['y']
                response.headers['X'] = value  # header-finding
            ''',
            'positive-guard': r'''
                value = request.args['x']
                if '\r' not in value and '\n' not in value:
                    response.headers['X'] = value
            ''',
            'guard-operand-rebinds-value': r'''
                value = request.args['old']
                if '\r' not in value and '\n' not in value and (value := request.args['fresh']):
                    response.headers['X'] = value  # header-finding
            ''',
            'caught-rejection': r'''
                value = request.args['x']
                try:
                    if '\r' in value or '\n' in value: raise ValueError('header')
                except ValueError:
                    pass
                response.headers['X'] = value  # header-finding
            ''',
        })

    def test_replacement_proofs_transfer_across_helpers(self):
        self.check_cases({
            'direct-replacement-chain': r'''
                response.headers['X'] = request.args['x'].replace('\r', '').replace('\n', '')
            ''',
            'split-replacement-proof': r'''
                def remove_lf(value): return value.replace('\n', '')
                response.headers['X'] = remove_lf(request.args['x'].replace('\r', ''))
            ''',
            'bounded-replacement': r'''
                response.headers['X'] = request.args['x'].replace('\r', '', 1).replace('\n', '')  # header-finding
            ''',
            'negative-count-replacement': r'''
                response.headers['X'] = request.args['x'].replace('\r', '', -1).replace('\n', '')
            ''',
            'replace-pair-only': r'''
                response.headers['X'] = request.args['x'].replace('\r\n', '')  # header-finding
            ''',
            'replacement-introduces-control': r'''
                from urllib.parse import quote
                response.headers['X'] = quote(request.args['x']).replace('x', '\n')  # header-finding
            ''',
        })

    def test_encoder_identity_options_and_decoding(self):
        self.check_cases({
            'trusted-encoder-alias': '''
                from urllib.parse import quote_plus as escaped
                response.headers['X'] = escaped(request.args['x'])
            ''',
            'trusted-module-alias': '''
                from urllib import parse as encoder
                response.headers['X'] = encoder.quote(request.args['x'], safe='')
            ''',
            'trusted-filename': '''
                from werkzeug.utils import secure_filename as clean
                send_file('fixed.pdf', download_name=clean(request.args['x']))
            ''',
            'unsafe-safe-argument': r'''
                from urllib.parse import quote
                response.headers['X'] = quote(request.args['x'], safe='\r\n')  # header-finding
            ''',
            'unknown-safe-argument': '''
                from urllib.parse import quote
                response.headers['X'] = quote(request.args['x'], safe=configuration)  # header-finding
            ''',
            'shadowed-import': '''
                from urllib.parse import quote
                quote = lambda value: value
                response.headers['X'] = quote(request.args['x'])  # header-finding
            ''',
            'decode-in-helper': '''
                from urllib.parse import quote, unquote
                def decoded(value): return unquote(value)
                response.headers['X'] = decoded(quote(request.args['x']))  # header-finding
            ''',
            'reencode-after-decode': '''
                from urllib.parse import quote, unquote
                def rebuilt(value): return quote(unquote(value))
                response.headers['X'] = rebuilt(quote(request.args['x']))
            ''',
        })

    def test_control_reintroduction_invalidates_old_proofs(self):
        expressions = {
            'literal-control': r"safe + '\r\n'",
            'chr-control': 'safe + chr(13) + chr(10)',
            'fstring-chr-control': 'f"{safe}{chr(13)}{chr(10)}"',
            'fstring-character-format': 'f"{safe}{13:c}{10:c}"',
            'format-character-control': '"{}{:c}{:c}".format(safe, 13, 10)',
            'format-container-selector': r'''"{0[safe]}{0[bad]}".format({'safe': safe, 'bad': '\r\nInjected: yes'})''',
            'percent-character-control': 'safe + "%c%c" % (13, 10)',
            'percent-width-character-control': 'safe + "%05c%05c" % (13, 10)',
            'container-projection-control': r'''safe + {'good': safe, 'bad': '\r\n'}['bad']''',
            'helper-control': 'append_control(safe)',
        }
        self.check_cases({name: (
            'from urllib.parse import quote\n'
            'def append_control(value): return value + "\\r"\n'
            'safe = quote(request.args["x"])\n'
            f'response.headers["X"] = {expression}  # header-finding\n'
        ) for name, expression in expressions.items()})
        self.check_cases({'fixed-composition': '''
            from urllib.parse import quote
            def add_suffix(value): return value + '.txt'
            safe = quote(request.args['x'])
            response.headers['X'] = f'attachment; filename="{add_suffix(safe)}"'
        '''})

    def test_namespace_mutations_and_captured_originals(self):
        mutations = {
            'direct-namespace-write': "encoder.quote = lambda value: value",
            'setattr-namespace-write': "setattr(encoder, 'quote', lambda value: value)",
            'dict-namespace-write': "encoder.__dict__['quote'] = lambda value: value",
            'global-helper-write': "def change(): encoder.quote = lambda value: value\nchange()",
            'parameter-helper-write': "def change(module): module.quote = lambda value: value\nchange(encoder)",
        }
        self.check_cases({name: (
            'import urllib.parse as encoder\n'
            'saved = encoder.quote\n'
            f'{mutation}\n'
            'response.headers["X"] = encoder.quote(request.args["x"])  # header-finding\n'
            'response.headers["Y"] = saved(request.args["y"])\n'
        ) for name, mutation in mutations.items()})
        self.check_cases({
            'star-shadows-import': '''
                from urllib.parse import quote
                from unknown import *
                response.headers['X'] = quote(request.args['x'])  # header-finding
            ''',
            'mutation-before-another-helper': '''
                import urllib.parse as encoder
                def change(): encoder.quote = lambda value: value
                def emit(value): response.headers['X'] = encoder.quote(value)  # header-finding
                def run():
                    change()
                    emit(request.args['x'])
            ''',
            'callee-captured-before-mutating-argument': '''
                import urllib.parse as encoder
                def change():
                    encoder.quote = lambda value: value
                    return request.args['x']
                response.headers['X'] = encoder.quote(change())
            ''',
        })

    def test_names_values_aliases_and_factory_sinks(self):
        self.check_cases({
            'header-name-assignment': '''
                response.headers[request.args['key']] = 'fixed'  # header-finding
            ''',
            'header-name-factory': '''
                from flask import Response
                Response('ok', headers={request.args['key']: 'fixed'})  # header-finding
            ''',
            'header-name-method': '''
                response.headers.add(request.args['key'], 'fixed')  # header-finding
            ''',
            'header-object-alias': '''
                headers_alias = response.headers
                headers_alias['X'] = request.args['x']  # header-finding
            ''',
            'header-alias-helper': '''
                def emit(mapping, value): mapping['X'] = value  # header-finding
                emit(response.headers, request.args['x'])
            ''',
            'response-object-alias': '''
                from django.http import HttpResponse as Reply
                result = Reply('ok')
                result[request.args['key']] = 'fixed'  # header-finding
            ''',
            'ordinary-dictionary': '''
                data = {}
                data['Content-Disposition'] = request.args['x']
            ''',
        })

    def test_escaped_header_cells_keep_sources_and_caller_isolation(self):
        self.check_cases({
            'closure-direct-control': '''
                response.headers['X'] = request.args['x']  # header-finding
            ''',
            'escaped-header-source': '''
                def make(value):
                    def emit():
                        response.headers['X'] = value  # header-finding
                    return emit
                make(request.args['x'])()
            ''',
            'escaped-header-caller-collision': '''
                def make(value):
                    def emit(): response.headers['X'] = value
                    return emit
                emit = make('fixed')
                value = request.args['x']
                emit()
            ''',
            'unused-header-closure': '''
                def make(value):
                    def emit(): response.headers['X'] = value
                    return emit
                unused = make(request.args['x'])
            ''',
        })

    def test_escaped_header_encoders_keep_identity_and_proofs(self):
        self.check_cases({
            'captured-local-encoder-import': '''
                def make():
                    from urllib.parse import quote
                    def encode(value): return quote(value, safe='')
                    return encode
                response.headers['X'] = make()(request.args['x'])
            ''',
            'captured-encoded-value': '''
                from urllib.parse import quote
                def make(value):
                    def read(): return value
                    return read
                response.headers['X'] = make(quote(request.args['x']))()
            ''',
            'captured-shadowed-encoder': '''
                from urllib.parse import quote
                def identity(value): return value
                def make(quote):
                    def encode(value): return quote(value)
                    return encode
                response.headers['X'] = make(identity)(request.args['x'])  # header-finding
            ''',
            'escaped-decoder-revokes-proof': '''
                from urllib.parse import quote, unquote
                def make(value):
                    def read(): return unquote(value)
                    return read
                response.headers['X'] = make(quote(request.args['x']))()  # header-finding
            ''',
        })

    def test_escaped_header_guards_refine_lexical_cells(self):
        self.check_cases({
            'guard-inside-escaped-closure': r'''
                def make(value):
                    def emit():
                        if '\r' in value or '\n' in value: raise ValueError('header')
                        response.headers['X'] = value
                    return emit
                make(request.args['x'])()
            ''',
            'guard-before-closure-creation': r'''
                def make(value):
                    if '\r' in value or '\n' in value: raise ValueError('header')
                    def emit(): response.headers['X'] = value
                    return emit
                make(request.args['x'])()
            ''',
            'escaped-guard-rejects-only-cr': r'''
                def make(value):
                    def emit():
                        if '\r' in value: raise ValueError('header')
                        response.headers['X'] = value  # header-finding
                    return emit
                make(request.args['x'])()
            ''',
        })

    def test_sibling_header_closures_share_nonlocal_replacements(self):
        factory = '''
            def make(value):
                def read(): return value
                def replace(new_value):
                    nonlocal value
                    value = new_value
                    return read
                return replace
        '''
        self.check_cases({
            'sibling-header-write-retains-source': factory + '''
            replace = make('fixed')
            read = replace(request.args['x'])
            response.headers['X'] = read()  # header-finding
            ''',
            'sibling-header-write-replaces-old-proof': factory + '''
            from urllib.parse import quote
            replace = make(request.args['old'])
            read = replace(quote(request.args['new']))
            response.headers['X'] = read()
            ''',
        })

    def test_existing_security_fixtures_keep_exact_locations(self):
        security = REPO_ROOT / 'test-suite/python/security'
        buggy = security / 'header_injection_buggy.py'
        clean = security / 'header_injection_clean.py'
        self.assertEqual([hit[1] for hit in header_injection.find([buggy])],
                         [7, 14, 20, 25, 30, 31, 37, 43, 48, 53])
        self.assertEqual(list(header_injection.find([clean])), [])

    def test_helper_sink_retains_source_to_sink_witness(self):
        source = self.work / 'helper-witness.py'
        source.write_text('def emit(value): response.headers["X"] = value\n'
                          'emit(request.args["x"])\n', encoding='utf-8')
        findings = list(header_injection.find([source]))
        self.assertEqual([item[1] for item in findings], [1])
        self.assertIn('request.args', findings[0][3])
        self.assertIn('emit()', findings[0][3])
        self.assertIn('response header', findings[0][3])

    def test_large_module_keeps_thirteen_late_security_findings(self):
        # 6,520 lines of independent, finite loops exceeded the old file-wide
        # expression cap. Each loop needs 81 passes to propagate the argument
        # across 80 slots; no individual function is an unbounded workload.
        slots = 80
        body = ''.join(f'    v{index} = ""\n' for index in range(slots))
        body += '    while enabled:\n'
        body += ''.join(f'        v{index} = v{index + 1}\n' for index in range(slots - 1))
        body += f'        v{slots - 1} = value\n    return v0\n'
        prefix = ''.join(f'def process_{index}(value):\n' + body for index in range(40))
        helpers = ('from urllib.parse import quote, unquote\n'
                   'def relay(value): return value\n'
                   'def encode(value): return quote(value, safe="")\n')
        payloads = ('request.args["name"]', 'relay(request.args["name"])',
                    'process_39(request.args["name"])',
                    'unquote(encode(request.args["name"]))')
        planted = ''.join(
            f'def unsafe_{index}(request, response):\n'
            f'    response.headers["X-{index}"] = {payloads[index % len(payloads)]}  # header-finding\n'
            for index in range(13))
        clean = ('def safe(request, response):\n'
                 '    response.headers["X"] = encode(request.args["name"])\n')
        self.check_cases({'large-late-header-findings': prefix + helpers + planted + clean})

    def test_exhausted_function_keeps_other_functions_and_diagnostic(self):
        from unittest import mock

        source = ('def before(request, response):\n'
                  '    response.headers["Before"] = request.args["before"]\n'
                  'def expensive(value):\n' + '    value = str(value)\n' * 100 +
                  '    return value\n'
                  'def relay(value): return value\n'
                  'def after(request, response):\n'
                  '    response.headers["After"] = relay(request.args["after"])\n')
        path = self.work / 'limited-header-functions.py'
        path.write_text(source, encoding='utf-8')
        findings = []
        with mock.patch.dict(os.environ, {'UBS_PYTHON_FLOW_SCOPE_STEPS': '200'}), \
                self.assertRaisesRegex(RuntimeError, 'incomplete header analysis') as raised:
            findings.extend(header_injection.find([path]))
        self.assertEqual([line for _, line, _, _ in findings], [2, len(source.splitlines())])
        self.assertIn('expensive', str(raised.exception))
        self.assertIn('lines 3-104', str(raised.exception))
        self.assertIn('limited-header-functions.py', str(raised.exception))
        self.assertIn('200', str(raised.exception))

    def test_exhausted_helper_keeps_observed_parameterized_sink(self):
        from unittest import mock

        helper = ('from urllib.parse import quote\n'
                  'def expensive(value, response):\n'
                  '    response.headers["X"] = value\n' +
                  '    value = str(value)\n' * 100 + '    return value\n')
        for label, argument, expected in (
                ('unsafe', 'request.args["x"]', [3]),
                ('encoded', 'quote(request.args["x"], safe="")', [])):
            with self.subTest(case=label):
                path = self.work / f'limited-helper-{label}.py'
                path.write_text(helper + 'def view(request, response):\n'
                                f'    expensive({argument}, response)\n', encoding='utf-8')
                findings = []
                with mock.patch.dict(os.environ, {'UBS_PYTHON_FLOW_SCOPE_STEPS': '200'}), \
                        self.assertRaisesRegex(RuntimeError, 'incomplete header analysis.*expensive'):
                    findings.extend(header_injection.find([path]))
                self.assertEqual([line for _, line, _, _ in findings], expected)
                if findings:
                    self.assertIn('request.args', findings[0][3])
                    self.assertIn('response header', findings[0][3])

    def test_coroutine_summaries_preserve_sinks_and_encoder_proofs(self):
        self.check_cases({
            'awaited-header-return': '''
                async def relay(value): return value
                async def view(request, response):
                    response.headers['X'] = await relay(request.args['x'])  # header-finding
            ''',
            'awaited-header-sink': '''
                async def emit(value, response):
                    response.headers['X'] = value  # header-finding
                async def view(request, response):
                    await emit(request.args['x'], response)
            ''',
            'unawaited-header-sink': '''
                async def emit(value, response):
                    response.headers['X'] = value
                def view(request, response):
                    emit(request.args['x'], response)
            ''',
            'awaited-header-encoder': '''
                from urllib.parse import quote
                async def encode(value): return quote(value, safe='')
                async def view(request, response):
                    response.headers['X'] = await encode(request.args['x'])
            ''',
            'asyncio-run-header-return': '''
                import asyncio
                async def relay(value): return value
                def view(request, response):
                    response.headers['X'] = asyncio.run(relay(request.args['x']))  # header-finding
            ''',
        })

    def test_exhausted_coroutines_preserve_actual_arguments_and_revoke_proofs(self):
        from unittest import mock

        helper = ('from urllib.parse import quote, unquote\n'
                  'import asyncio\n'
                  'async def expensive(value):\n'
                  '    value = unquote(value)\n' +
                  '    value = str(value)\n' * 100 + '    return value\n')
        for label, handler, result in (
                ('await', 'async def view(request, response):',
                 'await expensive(request.args["x"])'),
                ('encoded-await', 'async def view(request, response):',
                 'await expensive(quote(request.args["x"], safe=""))'),
                ('run', 'def view(request, response):',
                 'asyncio.run(expensive(request.args["x"]))')):
            with self.subTest(case=label):
                source = helper + handler + f'\n    response.headers["X"] = {result}\n'
                path = self.work / f'limited-coroutine-{label}.py'
                path.write_text(source, encoding='utf-8')
                findings = []
                with mock.patch.dict(os.environ, {'UBS_PYTHON_FLOW_SCOPE_STEPS': '200'}), \
                        self.assertRaisesRegex(RuntimeError, 'incomplete header analysis.*expensive'):
                    findings.extend(header_injection.find([path]))
                self.assertEqual([line for _, line, _, _ in findings], [len(source.splitlines())])
                self.assertIn('request.args', findings[0][3])

    def test_exhausted_coroutines_retain_shared_taint_provenance(self):
        from unittest import mock

        helper = ('import os, asyncio\n'
                  'async def expensive(value):\n' + '    value = str(value)\n' * 100 +
                  '    return value\n')
        for label, handler, result in (
                ('await', 'async def view():', 'await expensive(input())'),
                ('run', 'def view():', 'asyncio.run(expensive(input()))')):
            with self.subTest(case=label):
                source = helper + handler + f'\n    os.system({result})\n'
                path = self.work / f'limited-taint-coroutine-{label}.py'
                path.write_text(source, encoding='utf-8')
                findings = []
                with mock.patch.dict(os.environ, {'UBS_PYTHON_FLOW_SCOPE_STEPS': '200'}), \
                        self.assertRaisesRegex(header_injection.flow.AnalysisLimit,
                                               'incomplete.*expensive'):
                    findings.extend(header_injection.flow.scan_file_findings(path))
                self.assertEqual([(rule, line) for rule, line, _, _ in findings],
                                 [('py.taint.command', len(source.splitlines()))])
                self.assertIn('input(', findings[0][3])

    def test_sink_scoped_suppression_and_structural_prefilter(self):
        from unittest import mock
        self.check_cases({'header-suppressions': '''
            value = request.args['x']  # ubs:ignore[py.security.header-injection]
            response.headers['X'] = value  # header-finding
            response.headers['Y'] = value  # ubs:ignore[py.security.header-injection]
            response.headers['Z'] = value  # ubs:ignore[py.sql-injection]  # header-finding
        '''})
        irrelevant = self.work / 'no-header-sink.py'
        irrelevant.write_text('text = "response.headers[value] = request.args"\n'
                              'tree = ast.parse(text, filename=path)\n'
                              'index.formatter_headers[line] = parsed\n', encoding='utf-8')
        with mock.patch.object(header_injection, '_HeaderAnalysis') as analyzer:
            self.assertEqual(list(header_injection.find([irrelevant])), [])
            analyzer.assert_not_called()

    def test_parse_and_budget_failures_keep_independent_findings(self):
        from unittest import mock
        bad = self.work / 'malformed.py'
        good = self.work / 'independent.py'
        bad.write_text('response.headers[ = request.args["x"]\n', encoding='utf-8')
        good.write_text('response.headers["X"] = request.args["x"]\n', encoding='utf-8')
        for paths in ([bad, good], [good, bad]):
            findings = header_injection.find(paths)
            self.assertEqual(next(findings)[:3], (good, 1, 1))
            with self.assertRaisesRegex(RuntimeError, 'incomplete header analysis.*SyntaxError'):
                next(findings)
        with mock.patch.dict(os.environ, {'UBS_PYTHON_FLOW_MAX_STEPS': '1'}):
            with self.assertRaisesRegex(RuntimeError, 'incomplete header analysis.*work limit'):
                list(header_injection.find([good]))

    def test_shared_work_limit_keeps_earlier_and_later_header_findings(self):
        from unittest import mock
        from ubs_core.taint_flow import Budget

        paths = [self.work / name for name in ('before-limit.py', 'at-limit.py', 'after-limit.py')]
        for path in paths:
            path.write_text('def emit(value): response.headers["X"] = value\n'
                            'emit(request.args["x"])\n', encoding='utf-8')
        findings = []
        with mock.patch.object(header_injection.flow, 'Budget',
                               side_effect=[Budget(), Budget(0), Budget()]), \
                self.assertRaisesRegex(RuntimeError, 'incomplete header analysis.*AnalysisLimit') as raised:
            findings.extend(header_injection.find(paths))
        self.assertEqual([(path.name, line, column) for path, line, column, _ in findings],
                         [('before-limit.py', 1, 18), ('after-limit.py', 1, 18)])
        self.assertTrue(all('request.args' in detail and 'response header' in detail
                            for _, _, _, detail in findings), findings)
        self.assertIn('at-limit.py', str(raised.exception))
        self.assertIn('work limit exceeded', str(raised.exception))


@unittest.skipUnless(os.environ.get('UBS_PY_LDAP_E2E') == '1',
                     'set UBS_PY_LDAP_E2E=1 for actual LDAP CLI scans')
class LDAPInjectionPublicTests(unittest.TestCase):
    def test_module_and_runner_json_sarif_preserve_findings_and_partial_status(self):
        artifacts = REPO_ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix='python-ldap-public-', dir=artifacts))
        unsafe = ('from ldap3 import Connection\n'
                  'directory = Connection("directory.invalid")\n'
                  'def lookup(value): directory.search("dc=example", value)\n'
                  'lookup(request.args["filter"])\n')
        clean = ('from ldap3.utils.conv import escape_filter_chars as encode\n'
                 'def prepare(value): return encode(value)\n' + unsafe.replace(
                     'lookup(request.args["filter"])', 'lookup(prepare(request.args["filter"]))'))
        limited = ('def expensive(value):\n' + '    value = str(value)\n' * 100 +
                   '    return value\n' + unsafe)
        env = {**os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'UBS_ENABLE_AUTO_UPDATE': '0',
               'UBS_NO_CACHE': '1', 'CI': '1', 'NO_COLOR': '1',
               'XDG_DATA_HOME': str(work / 'data'), 'XDG_CONFIG_HOME': str(work / 'config'),
               'XDG_CACHE_HOME': str(work / 'cache'), 'PYTHONDONTWRITEBYTECODE': '1'}
        skip = '--skip=' + ','.join(str(i) for i in range(1, 24) if i != 7)
        for label, source, expected, partial in (
                ('unsafe', unsafe, [3], False), ('clean', clean, [], False),
                ('suppressed', unsafe.replace('value)\n', 'value)  # ubs:ignore[py.security.ldap-injection]\n'), [], False),
                ('partial', unsafe, [3], True), ('limited', limited, [105], True)):
            selected = work / label
            selected.mkdir()
            path = selected / 'view.py'
            path.write_text(source, encoding='utf-8')
            if label == 'partial':
                (selected / 'malformed.py').write_text('directory.search( = input()\n', encoding='utf-8')
            run_env = {**env, 'UBS_PYTHON_FLOW_SCOPE_STEPS': '200'} if label == 'limited' else env
            surfaces = (True,) if os.environ.get('UBS_PY_LDAP_MODULE_ONLY') == '1' else (True, False)
            for module in surfaces:
                for fmt in ('json', 'sarif'):
                    with self.subTest(case=label, module=module, format=fmt):
                        prefix = (('bash', str(REPO_ROOT / 'modules/ubs-python.sh'), '--no-uv')
                                  if module else ('bash', str(REPO_ROOT / 'ubs'), '--only=python'))
                        command = (*prefix, '--ci', '--format=' + fmt, skip, str(selected))
                        result = subprocess.run(command, cwd=work, env=run_env, capture_output=True,
                                                text=True, timeout=180)
                        output = work / f'{label}-{module}-{fmt}'
                        output.with_suffix('.stdout').write_text(result.stdout, encoding='utf-8')
                        output.with_suffix('.stderr').write_text(result.stderr, encoding='utf-8')
                        self.assertEqual(result.returncode, 2 if partial else int(bool(expected)),
                                         (command, result.stdout, result.stderr))
                        payload = json.loads(result.stdout)
                        if fmt == 'json':
                            self.assertEqual(payload['status'], 'partial' if partial else 'ok', payload)
                            rows = [row for row in payload.get('findings', [])
                                    if row['rule' if module else 'rule_id'] == ldap_injection.RULE_ID]
                            samples = ([sample for row in rows for sample in row['samples']]
                                       if module else rows)
                            self.assertEqual([row['line'] for row in samples], expected, payload)
                            self.assertEqual(payload['critical'] if module else payload['totals']['critical'],
                                             len(expected), payload)
                            for sample in samples:
                                self.assertEqual(Path(sample['file']).name, path.name)
                            for row in rows:
                                message = row['title' if module else 'message']
                                self.assertIn('request.args', message)
                                self.assertIn('LDAP filter', message)
                        else:
                            rows = [row for run in payload['runs'] for row in run.get('results', [])
                                    if row['ruleId'] == ldap_injection.RULE_ID]
                            self.assertEqual([row['locations'][0]['physicalLocation']['region']['startLine']
                                              for row in rows], expected, payload)
                            invocations = [item for run in payload['runs'] for item in run.get('invocations', [])]
                            if partial:
                                self.assertTrue(invocations, payload)
                                self.assertTrue(all(item['executionSuccessful'] is False for item in invocations), payload)
                            else:
                                self.assertTrue(all(item.get('executionSuccessful') is not False
                                                    for item in invocations), payload)
                        print('PYTHON_LDAP_PUBLIC', label, module, fmt, 'PASS', flush=True)

    def test_runner_cache_edits_suppression_and_partial_nonreuse(self):
        artifacts = REPO_ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix='python-ldap-cache-', dir=artifacts))
        target = work / 'view.py'
        unsafe = ('from ldap3 import Connection\n'
                  'directory = Connection("directory.invalid")\n'
                  'Connection.search(directory, "dc=example", request.args["filter"])\n')
        clean = unsafe.replace('request.args["filter"]', '"(uid=fixed)"')
        suppressed = unsafe.rstrip('\n') + '  # ubs:ignore[py.security.ldap-injection]\n'
        partial = unsafe + 'directory.search = external_search\n'
        env = {**os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'UBS_ENABLE_AUTO_UPDATE': '0',
               'UBS_NO_CACHE': '0', 'UBS_CACHE_DIR': str(work / 'scan-cache'), 'UBS_PROFILE': '1',
               'CI': '1', 'NO_COLOR': '1', 'PYTHONDONTWRITEBYTECODE': '1',
               'XDG_DATA_HOME': str(work / 'data'), 'XDG_CONFIG_HOME': str(work / 'config'),
               'XDG_CACHE_HOME': str(work / 'cache')}
        skip = '--skip=' + ','.join(str(i) for i in range(1, 24) if i != 7)
        command = ('bash', str(REPO_ROOT / 'ubs'), '--only=python', '--ci', '--format=json', skip, str(target))
        cases = (
            ('cold', unsafe, [3], False, 0), ('warm', unsafe, [3], False, 1),
            ('clean-edit', clean, [], False, 0), ('restored', unsafe, [3], False, 1),
            ('suppressed', suppressed, [], False, 0),
            ('partial-first', partial, [3], True, 0), ('partial-repeat', partial, [3], True, 0),
        )
        for index, (label, source, lines, incomplete, hits) in enumerate(cases):
            with self.subTest(case=label):
                if index not in (1, 6):
                    target.write_text(source, encoding='utf-8')
                result = subprocess.run(command, cwd=work, env=env, capture_output=True,
                                        text=True, timeout=180)
                output = work / f'{index}-{label}'
                output.with_suffix('.stdout').write_text(result.stdout, encoding='utf-8')
                output.with_suffix('.stderr').write_text(result.stderr, encoding='utf-8')
                self.assertEqual(result.returncode, 2 if incomplete else int(bool(lines)),
                                 (command, result.stdout, result.stderr))
                payload = json.loads(result.stdout)
                self.assertEqual(payload['status'], 'partial' if incomplete else 'ok', payload)
                rows = payload.get('findings', [])
                self.assertEqual([(row['rule_id'], row['line'], row['col']) for row in rows],
                                 [(ldap_injection.RULE_ID, line, 1) for line in lines], payload)
                self.assertEqual([payload['totals'][key] for key in ('files', 'critical', 'warning', 'info')],
                                 [1, len(lines), 0, 0], payload)
                for row in rows:
                    self.assertEqual(Path(row['file']).name, target.name, row)
                    self.assertEqual(row['severity'], 'critical', row)
                    self.assertFalse(row.get('suppressed', False), row)
                    self.assertIn('request.args', row['message'])
                    self.assertIn('LDAP filter', row['message'])
                self.assertEqual(payload['profile']['cache_hits'], hits, payload)
                self.assertEqual(payload['profile']['cache_misses'], 1 - hits, payload)
                if incomplete:
                    self.assertIn('native LDAP receiver or class mutation', result.stdout + result.stderr)
                print('PYTHON_LDAP_CACHE', label, 'hits', hits, 'misses', 1 - hits, 'PASS', flush=True)


@unittest.skipUnless(os.environ.get('UBS_PY_HEADER_E2E') == '1',
                     'set UBS_PY_HEADER_E2E=1 for actual header CLI scans')
class HeaderInjectionPublicTests(unittest.TestCase):
    def test_module_and_runner_json_sarif_preserve_findings_and_partial_status(self):
        artifacts = REPO_ROOT / 'test-suite/artifacts'
        artifacts.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix='python-header-public-', dir=artifacts))
        unsafe = ('def sanitize_header_value(value):\n    return value\n'
                  'def view(request, response):\n'
                  '    response.headers["X"] = sanitize_header_value(request.args["x"])\n')
        clean = ('from urllib.parse import quote as encoded\n'
                 'def prepare(value): return encoded(value, safe="")\n'
                 'def view(request, response):\n'
                 '    response.headers["X"] = prepare(request.args["x"])\n')
        limited = ('def expensive(value):\n' + '    value = str(value)\n' * 100 +
                   '    return value\n' + unsafe)
        env = {**os.environ, 'UBS_NO_AUTO_UPDATE': '1', 'UBS_ENABLE_AUTO_UPDATE': '0',
               'UBS_NO_CACHE': '1', 'CI': '1', 'NO_COLOR': '1',
               'XDG_DATA_HOME': str(work / 'data'), 'XDG_CONFIG_HOME': str(work / 'config'),
               'XDG_CACHE_HOME': str(work / 'cache'), 'PYTHONDONTWRITEBYTECODE': '1'}
        skip = '--skip=' + ','.join(str(i) for i in range(1, 24) if i != 7)
        for label, source, expected, partial in (
                ('unsafe', unsafe, [4], False), ('clean', clean, [], False),
                ('partial', unsafe, [4], True),
                ('limited', limited, [len(limited.splitlines())], True)):
            selected = work / label
            selected.mkdir()
            path = selected / 'view.py'
            path.write_text(source, encoding='utf-8')
            if label == 'partial':
                (selected / 'malformed.py').write_text('response.headers[ = input()\n', encoding='utf-8')
            run_env = {**env, 'UBS_PYTHON_FLOW_SCOPE_STEPS': '200'} if label == 'limited' else env
            for module in (True, False):
                for fmt in ('json', 'sarif'):
                    with self.subTest(case=label, module=module, format=fmt):
                        prefix = (('bash', str(REPO_ROOT / 'modules/ubs-python.sh'), '--no-uv')
                                  if module else ('bash', str(REPO_ROOT / 'ubs'), '--only=python'))
                        command = (*prefix, '--ci', '--format=' + fmt, skip, str(selected))
                        result = subprocess.run(command, cwd=work, env=run_env, capture_output=True,
                                                text=True, timeout=180)
                        output = work / f'{label}-{module}-{fmt}'
                        output.with_suffix('.stdout').write_text(result.stdout, encoding='utf-8')
                        output.with_suffix('.stderr').write_text(result.stderr, encoding='utf-8')
                        self.assertEqual(result.returncode, 2 if partial else int(bool(expected)),
                                         (command, result.stdout, result.stderr))
                        payload = json.loads(result.stdout)
                        if fmt == 'json':
                            self.assertEqual(payload['status'], 'partial' if partial else 'ok', payload)
                            rows = [row for row in payload.get('findings', [])
                                    if row['rule' if module else 'rule_id'] == header_injection.RULE_ID]
                            samples = ([sample for row in rows for sample in row['samples']]
                                       if module else rows)
                            self.assertEqual([row['line'] for row in samples], expected, payload)
                            self.assertEqual(payload['critical'] if module else payload['totals']['critical'],
                                             len(expected), payload)
                            for sample in samples:
                                self.assertEqual(Path(sample['file']).name, path.name)
                            for row in rows:
                                message = row['title' if module else 'message']
                                self.assertIn('request.args', message)
                                self.assertIn('response header', message)
                        else:
                            rows = [row for run in payload['runs'] for row in run.get('results', [])
                                    if row['ruleId'] == header_injection.RULE_ID]
                            self.assertEqual([row['locations'][0]['physicalLocation']['region']['startLine']
                                              for row in rows], expected, payload)
                            invocations = [item for run in payload['runs']
                                           for item in run.get('invocations', [])]
                            if partial:
                                self.assertTrue(invocations, payload)
                                self.assertTrue(all(item['executionSuccessful'] is False for item in invocations),
                                                payload)
                            else:
                                self.assertTrue(all(item.get('executionSuccessful') is not False
                                                    for item in invocations), payload)
                        print('PYTHON_HEADER_PUBLIC', label, module, fmt, 'PASS', flush=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
