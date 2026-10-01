#!/usr/bin/env python3
"""Python rule precision found by the v5.4.16 self-scan gate.

`./ubs . --ci --fail-on-warning` on the ubs checkout reported 9 criticals and
21 warnings that v5.4.9 did not. Most were rule defects any user would hit:

* ``python.ctcompare.secret_eq`` read code-shape signatures (``sig =
  self._call_signature(node)``), literal tuple keys (``sig == ("socket",
  "socketpair")``) and signal dispositions (``signal.SIG_DFL``) as secrets.
* ``py.security.shell-true`` reported a ``def`` whose parameter default is
  ``shell=True``; a signature declares an option and runs nothing.
* ``py.comparison.type-equality`` matched any call ending in ``type(`` (a
  method named ``exception_type``) and read ``is not`` as ``is`` against a type
  called ``not``. Both type rules reported ``type(n) is int``, the idiom that
  rejects bool where the suggested isinstance() would accept it.
* ``py.control-flow.finally-transfer`` matched the substring "return" in a
  comment, and code after the finally block had ended.
* ``py.functions.high-param-count`` counted ``self``, a bare ``*`` separator
  and the commas inside ``dict[str, int]`` as parameters.

Each test pins the false positive and a true positive of the same rule.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS_DIR = REPO_ROOT / "modules" / "helpers"
if str(HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(HELPERS_DIR))

from ubs_core.analyzers import ctcompare_py  # noqa: E402
from ubs_core.py_patterns.flow import PATTERNS as FLOW_PATTERNS  # noqa: E402
from ubs_core.py_patterns.foundations import PATTERNS as FOUNDATION_PATTERNS  # noqa: E402
from ubs_core.py_patterns.quality import PATTERNS as QUALITY_PATTERNS  # noqa: E402
from ubs_core.py_patterns.security_rg import PATTERNS as SECURITY_PATTERNS  # noqa: E402
from ubs_core.py_rules import _RULES  # noqa: E402
from ubs_core.py_scan import scan_patterns  # noqa: E402


class _Sink:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def write(self, line: str) -> None:
        self.records.append(json.loads(line))


def pattern_lines(rule_id: str, source: str) -> list[int]:
    """Lines one pattern reports in a single temporary module."""
    selected = [
        entry
        for group in (FLOW_PATTERNS, FOUNDATION_PATTERNS, QUALITY_PATTERNS, SECURITY_PATTERNS)
        for entry in group
        if entry.rule_id == rule_id
    ]
    if len(selected) != 1:
        raise AssertionError(f"expected one pattern {rule_id}, found {len(selected)}")
    with tempfile.TemporaryDirectory(prefix="ubs_selfscan_rules_") as tmp:
        target = Path(tmp) / "sample.py"
        target.write_text(textwrap.dedent(source).lstrip("\n"), encoding="utf-8")
        sink = _Sink()
        scan_patterns(selected, [target], sink, skip=set())
    return sorted(record["line"] for record in sink.records)


def ctcompare_lines(source: str) -> list[int]:
    code = textwrap.dedent(source).lstrip("\n")
    return [line for _path, line, _code in ctcompare_py._scan_code(code)]


class SecretCompareTests(unittest.TestCase):
    def test_code_signatures_tuple_keys_and_signal_dispositions_are_not_secrets(self) -> None:
        self.assertEqual(ctcompare_lines('''
            import signal
            def dispatch(self, node, completion):
                sig = self._call_signature(node)
                if sig == ("socket", "socketpair"):
                    return 1
                if sig[1] == "closing":
                    return 2
                if self._reference_signature(completion) == ("asyncio", "ALL_COMPLETED"):
                    return 3
                method_sig = inspect_method(node)
                return signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
        '''), [])

    def test_secret_comparisons_next_to_them_stay_reported(self) -> None:
        self.assertEqual(ctcompare_lines('''
            def check(request, sig, password, expected):
                webhook_signature = request.headers["X-Signature"]
                if webhook_signature == expected:
                    return 1
                if sig == expected:
                    return 2
                computed_sig = compute(request.body)
                if computed_sig == request.headers["X-Sig"]:
                    return 3
                if password == "hunter2":
                    return 4
                request_sig = self._call_signature(request)
                return request.sig == expected
        '''), [3, 5, 8, 10, 13])

    def test_reference_signature_is_still_the_expected_mac(self) -> None:
        self.assertEqual(ctcompare_lines('''
            def verify(reference_signature, body):
                return reference_signature == compute(body)
        '''), [2])

    def test_explained_name_does_not_leak_into_the_next_function(self) -> None:
        self.assertEqual(ctcompare_lines('''
            def first(node):
                sig = call_signature(node)
                return sig == ("a", "b")
            def second(sig, expected):
                return sig == expected
        '''), [5])


class ShellTrueTests(unittest.TestCase):
    RULE = "py.security.shell-true"

    def test_parameter_default_is_not_a_shell_call(self) -> None:
        self.assertEqual(pattern_lines(self.RULE, '''
            def expr_is_tainted(self, node, *, shell=True):
                return node
            async def run(cmd, shell=True) -> None:
                return None
        '''), [])

    def test_calls_with_shell_true_stay_reported(self) -> None:
        self.assertEqual(pattern_lines(self.RULE, '''
            import subprocess
            def one(cmd): subprocess.run(cmd, shell=True)
            subprocess.run(cmd, shell=True)
            def two(cmd, shell=True): subprocess.run(cmd, shell=True)
        '''), [2, 3, 4])


class TypeEqualityTests(unittest.TestCase):
    RULE = "py.comparison.type-equality"
    SOURCE = '''
        def f(self, x, n):
            a = type(x) == int
            b = type(x) is str
            c = type(n) is int
            d = type(n) is not int
            e = self.exception_type(x) is not None
            g = type(x) is frozenset
            h = type(x) is not str
            i = type(n) is intish
            return a, b, c, d, e, g, h, i
    '''

    def test_pattern_layer(self) -> None:
        # Reported: ==, other types, `is not str`, a name that only starts with
        # int. Silent: the bool-rejecting int identity checks and a method
        # whose name ends in "type".
        self.assertEqual(pattern_lines(self.RULE, self.SOURCE), [2, 3, 7, 8, 9])

    @unittest.skipUnless(shutil.which("ast-grep") or os.environ.get("UBS_AST_GREP_BIN"),
                         "ast-grep is not installed")
    def test_ast_grep_rule(self) -> None:
        sg = os.environ.get("UBS_AST_GREP_BIN") or shutil.which("ast-grep")
        with tempfile.TemporaryDirectory(prefix="ubs_selfscan_rules_") as tmp:
            rule = Path(tmp) / "rule.yml"
            rule.write_text(dict(_RULES)["type-equality"], encoding="utf-8")
            sample = Path(tmp) / "sample.py"
            sample.write_text(textwrap.dedent(self.SOURCE).lstrip("\n"), encoding="utf-8")
            proc = subprocess.run(
                [sg, "scan", "-r", str(rule), "--json=compact", str(sample)],
                capture_output=True, text=True, timeout=60, check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = sorted(match["range"]["start"]["line"] + 1 for match in json.loads(proc.stdout))
        # The pack rule never matched `is not`; it keeps == and `is` for every
        # type except the int identity idiom.
        self.assertEqual(lines, [2, 3, 7, 9])


class FinallyTransferTests(unittest.TestCase):
    RULE = "py.control-flow.finally-transfer"

    def test_comments_and_code_after_the_block_are_not_transfers(self) -> None:
        self.assertEqual(pattern_lines(self.RULE, '''
            def f(items):
                try:
                    run()
                finally:
                    cleanup()
                # returns survive the handler
                return 1
        '''), [])

    def test_transfers_inside_the_finally_block_stay_reported(self) -> None:
        self.assertEqual(pattern_lines(self.RULE, '''
            def f(items):
                for item in items:
                    try:
                        run(item)
                    finally:
                        # skip the rest
                        continue
            def g():
                try:
                    run()
                finally:
                    return 2
        '''), [5, 11])  # reported at the finally: header


class HighParamCountTests(unittest.TestCase):
    RULE = "py.functions.high-param-count"

    def test_receivers_separators_and_annotation_commas_are_not_parameters(self) -> None:
        # Seven of these would have been reported before; none has seven
        # real parameters. The rule reports from four matches upward.
        self.assertEqual(pattern_lines(self.RULE, '''
            class C:
                def assign(self, target, fact, state, value=None, *, target_references=None):
                    pass
                def call(self, name: str, expr: str, offset: int, call_offset: int, state, scope) -> tuple[int, ...]:
                    pass
                def m(self, a: dict[str, int], b: tuple[int, int], c, d, e, f):
                    pass
                def n(cls, a, b, c, d, e, f):
                    pass
            def k(a, b, c, d, e, /, f):
                pass
            def k2(a, b, c, d, e, *, f):
                pass
            def k3(a, b, c=f(1, 2), d=g(3, 4), e=None, f=None):
                pass
        '''), [])

    def test_seven_real_parameters_stay_reported(self) -> None:
        self.assertEqual(pattern_lines(self.RULE, '''
            class C:
                def native_call(self, expr, code, match, pairs, offset, state, scope, *, whole=False):
                    pass
                def invoke(self, node, state, target, fallback_name, receiver, receiver_refs,
                           arguments, keywords):
                    pass
            def add(start, params_start, params_end, body, name="", declaration=False, concise=False):
                pass
            def g(a, b, c, d, e, f, *args):
                pass
        '''), [2, 4, 7, 9])


if __name__ == "__main__":
    unittest.main(verbosity=2)
