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

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

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
        self.records.append(json.loads(line))  # ubs:ignore[py.parsing.json-loads-no-try] - malformed scanner output must fail the test


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


class PublicSignalCompareTests(unittest.TestCase):
    """GH #193: prove a local categorical signal; retain uncertain secrets."""

    def test_python39_ast_without_match_or_type_parameter_nodes(self) -> None:
        class LegacyAST:
            def __getattr__(self, name):
                if name in {'MatchAs', 'MatchStar', 'MatchMapping', 'TypeVar', 'ParamSpec', 'TypeVarTuple'}:
                    raise AttributeError(name)
                return getattr(ast, name)

            def parse(self, source):
                return ast.parse(source, feature_version=(3, 9))

        # Exercise the missing-attribute path as well as 3.9 source grammar;
        # this is not a substitute for running the supported Python runtime.
        with mock.patch.object(ctcompare_py, 'ast', LegacyAST()):
            self.assertEqual(ctcompare_lines('''
                def label():
                    observations = {"signal": "WATCH"}
                    market_sig = observations.get("signal")
                    return market_sig == "WATCH"
            '''), [])
            self.assertEqual(ctcompare_lines('''
                def verify(password):
                    return password == "hunter2"
            '''), [2])

    def test_issue_193_public_regime_labels(self) -> None:
        self.assertEqual(ctcompare_lines('''
            def public_regime_labels():
                rate_sens = {"rate_sensitivity_signal": "RATE_SENSITIVE"}
                equities = {"managed_care_signal": "CRISIS"}
                bdc_basket = {"signal": "WATCH"}
                rate_sig = rate_sens.get("rate_sensitivity_signal")
                mc_sig = equities.get("managed_care_signal")
                bdc_sig = bdc_basket.get("signal", "DATA_MISSING")
                return (
                    rate_sig is not None and rate_sig != "UNKNOWN",
                    mc_sig == "CRISIS",
                    bdc_sig == "CRISIS",
                    bdc_sig == "STRESS",
                    bdc_sig == "WATCH",
                )
        '''), [])

    def test_literal_signal_reads_and_immutable_aliases(self) -> None:
        self.assertEqual(ctcompare_lines('''
            async def labels():
                observations: dict[str, str] = {"signal": "WATCH", "credit_signal": "STRESS"}
                market_sig: str = observations["signal"]
                credit_sig = observations.get("credit_signal", None)
                label = market_sig
                saved_sig = label
                if saved_sig == "WATCH":
                    return credit_sig != "CRISIS"
                return market_sig == "UNKNOWN"
        '''), [])

    def test_literal_password_signature_and_security_roles_still_report(self) -> None:
        self.assertEqual(ctcompare_lines('''
            def verify(expected, secret):
                observations = {"signal": "WATCH"}
                market_sig = observations.get("signal")
                password = "hunter2"
                signature = "ABC123"
                auth_sig = observations.get("signal")
                webhook_sig = observations["signal"]
                return (
                    password == "hunter2",
                    signature == "ABC123",
                    auth_sig == "WATCH",
                    webhook_sig == "WATCH",
                    market_sig == secret,
                    expected == market_sig,
                )
        '''), [9, 10, 11, 12, 13])

    def test_unknown_or_dynamic_signal_values_remain_sensitive(self) -> None:
        cases = (
            ('observations = fetch_data()', 'observations.get("signal")'),
            ('observations = {"signal": compute()}', 'observations.get("signal")'),
            ('observations = {"signal": secret}', 'observations.get("signal")'),
            ('observations = {"signal": b"WATCH"}', 'observations.get("signal")'),
            ('observations = {"signal": "opaque-value"}', 'observations.get("signal")'),
            ('observations = {"signal": "WATCH"}', 'observations.get(field)'),
            ('observations = {"signal": "WATCH"}', 'observations.get("signal", secret)'),
            ('observations = {"signal": "WATCH"}', 'observations.get("missing_signal")'),
            ('observations = {"signal": "WATCH", **extra}', 'observations.get("signal")'),
            ('observations = {"signal": "WATCH", field: secret}', 'observations.get("signal")'),
            ('observations = {"signal": "WATCH", "signal": secret}', 'observations.get("signal")'),
            ('observations = {"auth_signal": "WATCH"}', 'observations.get("auth_signal")'),
            ('observations = {"signature": "WATCH"}', 'observations.get("signature")'),
            ('observations = {"signal": "SECRET"}', 'observations.get("signal")'),
        )
        for setup, value in cases:
            with self.subTest(setup=setup, value=value):
                self.assertEqual(ctcompare_lines(
                    f'def check(secret, field, extra):\n'
                    f'    {setup}\n'
                    f'    market_sig = {value}\n'
                    f'    return market_sig == "WATCH"\n'
                ), [4])
        self.assertEqual(ctcompare_lines('''
            def unknown(observations, sig):
                market_sig = observations.get("signal")
                return market_sig == "WATCH", sig == "WATCH"
        '''), [3])

    def test_mutation_and_escaping_maps_cannot_prove_public_values(self) -> None:
        changes = (
            'observations["signal"] = secret',
            'observations.update(signal=secret)',
            'observations.clear()',
            'alias = observations',
            'consume(observations)',
            'reader = observations.get',
            'observations |= {"signal": secret}',
            'del observations["signal"]',
        )
        for change in changes:
            with self.subTest(change=change):
                self.assertEqual(ctcompare_lines(
                    'def check(secret):\n'
                    '    observations = {"signal": "WATCH"}\n'
                    f'    {change}\n'
                    '    market_sig = observations.get("signal")\n'
                    '    return market_sig == "WATCH"\n'
                ), [5])
        self.assertEqual(ctcompare_lines('''
            def check(secret):
                observations = {"signal": "WATCH"}
                def replace():
                    observations["signal"] = secret
                replace()
                market_sig = observations.get("signal")
                return market_sig == "WATCH"
        '''), [7])

    def test_reassignment_is_conservative_before_and_after_the_write(self) -> None:
        self.assertEqual(ctcompare_lines('''
            def check(secret):
                observations = {"signal": "WATCH"}
                market_sig = observations.get("signal")
                first = market_sig == "WATCH"
                market_sig = secret
                return first, market_sig == "WATCH"
        '''), [4, 6])
        self.assertEqual(ctcompare_lines('''
            def check(secret):
                observations = {"signal": "WATCH"}
                market_sig = observations.get("signal")
                observations = {"signal": secret}
                return market_sig == "WATCH"
        '''), [5])

    def test_namespace_and_frame_reflection_defeats_local_proof(self) -> None:
        escapes = (
            'consume(locals())',
            'snapshot = locals\n    consume(snapshot())',
            'from builtins import locals as snapshot\n    consume(snapshot())',
            'consume(globals())',
            'consume(vars())',
            'exec(code)',
            'evaluate = eval\n    evaluate(code)',
            'import inspect\n    consume(inspect.currentframe())',
            'from inspect import currentframe as snapshot\n    consume(snapshot())',
            'import sys\n    consume(sys._getframe())',
            'consume(frame.f_locals)',
            'consume(__builtins__["locals"]())',
        )
        for escape in escapes:
            with self.subTest(escape=escape):
                code = (
                    'def check(code, frame):\n'
                    '    observations = {"signal": "WATCH"}\n'
                    f'    {escape}\n'
                    '    market_sig = observations.get("signal")\n'
                    '    return market_sig == "WATCH"\n'
                )
                self.assertEqual(ctcompare_lines(code), [len(code.splitlines())])

    def test_conditional_assignments_and_branch_order_do_not_create_proof(self) -> None:
        for first, second in (
            ('secret', 'observations.get("signal")'),
            ('observations.get("signal")', 'secret'),
        ):
            with self.subTest(first=first):
                self.assertEqual(ctcompare_lines(
                    'def check(condition, secret):\n'
                    '    observations = {"signal": "WATCH"}\n'
                    '    if condition:\n'
                    f'        market_sig = {first}\n'
                    '    else:\n'
                    f'        market_sig = {second}\n'
                    '    return market_sig == "WATCH"\n'
                ), [7])
        self.assertEqual(ctcompare_lines('''
            def check(condition):
                if condition:
                    observations = {"signal": "WATCH"}
                market_sig = observations.get("signal")
                return market_sig == "WATCH"
        '''), [5])
        self.assertEqual(ctcompare_lines('''
            def check(condition, secret):
                observations = {"signal": "WATCH"}
                market_sig = observations.get("signal")
                if condition:
                    market_sig = secret
                return market_sig == "WATCH"
        '''), [6])

    def test_loop_named_expression_import_and_handler_bindings_invalidate_proof(self) -> None:
        writes = (
            'for market_sig in values:\n        pass',
            'while (market_sig := next_value()):\n        break',
            'import some_module as market_sig',
            'try:\n        call()\n    except Error as market_sig:\n        pass',
        )
        if sys.version_info >= (3, 10):
            writes += ('match value:\n        case {"value": market_sig}:\n            pass',)
        for write in writes:
            with self.subTest(write=write):
                code = (
                    'def check(values, value):\n'
                    '    observations = {"signal": "WATCH"}\n'
                    '    market_sig = observations.get("signal")\n'
                    f'    {write}\n'
                    '    return market_sig == "WATCH"\n'
                )
                self.assertEqual(ctcompare_lines(code), [len(code.splitlines())])

    def test_function_scope_and_lambda_parameters_do_not_inherit_proof(self) -> None:
        self.assertEqual(ctcompare_lines('''
            def first():
                observations = {"signal": "WATCH"}
                market_sig = observations.get("signal")
                return market_sig == "WATCH"
            def second(market_sig):
                return market_sig == "WATCH"
            def outer():
                observations = {"signal": "WATCH"}
                market_sig = observations.get("signal")
                def inner(candidate_sig):
                    return candidate_sig == "WATCH"
                return market_sig == "WATCH"
            def shadow():
                observations = {"signal": "WATCH"}
                market_sig = observations.get("signal")
                return lambda market_sig: market_sig == "WATCH"
        '''), [6, 11, 16])
        self.assertEqual(ctcompare_lines('''
            observations = {"signal": "WATCH"}
            market_sig = observations.get("signal")
            def check():
                return market_sig == "WATCH"
        '''), [4])

    def test_global_nonlocal_and_generic_scope_bindings_remain_conservative(self) -> None:
        self.assertEqual(ctcompare_lines('''
            def global_label():
                global market_sig
                observations = {"signal": "WATCH"}
                market_sig = observations.get("signal")
                return market_sig == "WATCH"
            def outer():
                market_sig = "UNKNOWN"
                def inner():
                    nonlocal market_sig
                    observations = {"signal": "WATCH"}
                    market_sig = observations.get("signal")
                    return market_sig == "WATCH"
        '''), [5, 12])
        if sys.version_info >= (3, 12):
            self.assertEqual(ctcompare_lines('''
                def outer():
                    observations = {"signal": "WATCH"}
                    market_sig = observations.get("signal")
                    class Container[market_sig]:
                        value = market_sig == "WATCH"
                    return Container
            '''), [5])

    def test_sensitive_comparison_operands_and_keyed_digests_win(self) -> None:
        self.assertEqual(ctcompare_lines('''
            import hashlib
            import hmac
            def check(secret, payload, unknown, expected_signature):
                observations = {"signal": "WATCH"}
                market_sig = observations.get("signal")
                return (
                    market_sig == expected_signature,
                    hmac.new(secret, payload).hexdigest() == market_sig,
                    market_sig == hashlib.blake2b(payload, key=secret).digest(),
                    hashlib.sha256(secret).hexdigest() == market_sig,
                    market_sig == unknown.digest(),
                    hashlib.sha256(payload).hexdigest() == market_sig,
                )
        '''), [7, 8, 9, 10, 11])

    def test_binding_is_not_explained_before_its_assignment(self) -> None:
        self.assertEqual(ctcompare_lines('''
            def check():
                before = market_sig == "WATCH"
                observations = {"signal": "WATCH"}
                market_sig = observations.get("signal")
                return before, market_sig == "WATCH"
        '''), [2])


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
            proc = subprocess.run(  # ubs:ignore[py.security.command-injection,python.taint.command] - operator-selected ast-grep executable; fixed argv list, no shell
                [sg, "scan", "-r", str(rule), "--json=compact", str(sample)],
                capture_output=True, text=True, timeout=60, check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = sorted(match["range"]["start"]["line"] + 1 for match in json.loads(proc.stdout))  # ubs:ignore[py.parsing.json-loads-no-try] - malformed scanner output must fail the test
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
