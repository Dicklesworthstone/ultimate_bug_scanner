"""ubs_core.selftest — embedded unit tests for the core library and every analyzer (bead A2).

`python3 -m ubs_core --self-test` runs every registered analyzer's self-tests plus
core-library smoke tests. Each test prints a `[ubs_core] PASS/FAIL name` line so a
failure is diagnosable from the log alone.
"""
from __future__ import annotations

import sys
import traceback


def _core_lib_tests() -> list[tuple[str, callable]]:
    from ubs_core.io import find_block_end, line_col
    from ubs_core.lexer import Span, strip_comments_and_strings

    def test_line_col() -> None:
        text = "ab\ncd"
        assert line_col(text, 0) == (1, 1)
        assert line_col(text, 3) == (2, 1)
        assert line_col(text, 99) == (2, 3)

    def test_find_block_end() -> None:
        text = "{ a { b } c }"
        assert text[find_block_end(text, 0)] == "}"

    def test_span() -> None:
        span = Span(0, 3)
        assert span.length == 3 and span.contains(2) and not span.contains(3)

    def test_strip_preserves_shape() -> None:
        code = 'x = 1  # note\ny = "s"\n'
        out = strip_comments_and_strings(code, lang="python")
        assert len(out) == len(code)
        assert out.count("\n") == code.count("\n")
        assert "note" not in out and "s" not in out

    def test_suppression_trailing_and_prev() -> None:
        from ubs_core.suppression import build_index

        idx = build_index('def a(x=[]):  # ubs:ignore\n    return x\n', lang="python")
        assert idx.is_suppressed(1, "py.mutable")
        idx2 = build_index('# ubs:ignore\neval(x)\n', lang="python")
        assert idx2.is_suppressed(2, "py.eval")

    def test_suppression_multiline_statement() -> None:
        from ubs_core.suppression import build_index

        idx = build_index('eval(\n    # ubs:ignore\n    x)\n', lang="python")
        assert idx.is_suppressed(1, "py.eval")

    return [
        ("core.io.line_col", test_line_col),
        ("core.io.find_block_end", test_find_block_end),
        ("core.lexer.span", test_span),
        ("core.lexer.strip_preserves_shape", test_strip_preserves_shape),
        ("core.suppression.trailing_and_prev", test_suppression_trailing_and_prev),
        ("core.suppression.multiline_statement", test_suppression_multiline_statement),
    ]


def run_self_tests() -> int:
    from ubs_core import analyzers  # noqa: F401  (populate registry)
    from ubs_core.registry import all_analyzers

    tests: list[tuple[str, callable]] = list(_core_lib_tests())
    for analyzer in all_analyzers():
        tests.extend((f"{analyzer.name}.{name}", fn) for name, fn in analyzer.selftests)

    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception:  # noqa: BLE001 — report and continue
            failures += 1
            print(f"[ubs_core] FAIL {name}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        else:
            print(f"[ubs_core] PASS {name}")

    total = len(tests)
    print(f"[ubs_core] self-test summary: {total - failures}/{total} passed")
    return 1 if failures else 0
