"""ubs_core.analyzers.regex_swift — Swift resource-lifecycle regex fallback (bead A2).

Logic moved verbatim from the fallback heredoc in modules/ubs-swift.sh
(run_resource_lifecycle_checks, `cat >"$tmp_py" <<'PY'` block), which remains in
place until that module's port bead; transitional duplication is sanctioned.
Also exposes a structured `run(ctx)` for the `python3 -m ubs_core` CLI.

Emit dialect: `path\tkind\tacquire=N cleanup=M` per imbalanced file/kind.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

RULES = {
  "timer": (re.compile(r"Timer\.scheduledTimer"), re.compile(r"\.invalidate\s*\(")),
  "urlsession_task": (re.compile(r"\.(dataTask|uploadTask|downloadTask)\s*\("), re.compile(r"\.(resume|cancel)\s*\(")),
  "notification_token": (re.compile(r"NotificationCenter\.default\.addObserver\([^)]*(using:\s*\{|forName:)"), re.compile(r"removeObserver\s*\(")),
  "file_handle": (re.compile(r"FileHandle\s*\(\s*for(Reading|Writing|Updating)(From|To|AtPath)\s*:"), re.compile(r"\.close\s*\(")),
  "combine_sink": (re.compile(r"\.sink\s*\("), re.compile(r"\.store\s*\(\s*in:\s*&")),
  "dispatch_source": (re.compile(r"DispatchSource\.(makeTimerSource|makeFileSystemObjectSource|makeReadSource|makeWriteSource)"), re.compile(r"(\.cancel|\.(resume))\s*\(")),
  "cadisplaylink": (re.compile(r"CADisplayLink\s*\("), re.compile(r"\.invalidate\s*\(")),
  "kvo_observer": (re.compile(r"addObserver\([^)]*forKeyPath:"), re.compile(r"removeObserver\([^)]*forKeyPath:")),
}

_SUFFIXES = (".swift", ".mm", ".m")
_SUFFIX_SET = frozenset(_SUFFIXES)

_SEVERITY = {
    "timer": "warning",
    "urlsession_task": "warning",
    "notification_token": "warning",
    "file_handle": "critical",
    "combine_sink": "warning",
    "dispatch_source": "warning",
    "cadisplaylink": "warning",
    "kvo_observer": "warning",
}


def scan_text(text: str) -> list[tuple[str, int, int]]:
    """Return (kind, acquire_count, cleanup_count) imbalances for one file's text."""
    found: list[tuple[str, int, int]] = []
    for kind, (acq, rel) in RULES.items():
        ac = len(acq.findall(text))
        rl = len(rel.findall(text))
        if ac > rl:
            found.append((kind, ac, rl))
    return found


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: regex_swift.py <project_dir>", file=sys.stderr)
        return 2
    root = sys.argv[1]
    for dp, _, fs in os.walk(root):
        for fn in fs:
            if not fn.endswith(_SUFFIXES):
                continue
            p = os.path.join(dp, fn)
            try:
                s = open(p, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for kind, ac, rl in scan_text(s):
                print(f"{p}\t{kind}\tacquire={ac} cleanup={rl}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix not in _SUFFIX_SET:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for kind, ac, rl in scan_text(text):
            try:
                rel = path.relative_to(cwd)
            except ValueError:
                rel = path
            yield {
                "rule": f"swift.regex.{kind}",
                "path": str(rel),
                "line": 0,
                "col": 0,
                "layer": "regex",
                "lang": "swift",
                "severity": _SEVERITY[kind],
                "message": f"acquire={ac} cleanup={rl}",
            }


def _selftest_timer_positive() -> None:
    code = (
        "import Foundation\n"
        "class A {\n"
        "  func start() {\n"
        "    Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }\n"
        "  }\n"
        "}\n"
    )
    assert scan_text(code) == [("timer", 1, 0)], scan_text(code)


def _selftest_invalidated_suppression() -> None:
    code = (
        "class A {\n"
        "  var t: Timer?\n"
        "  func start() { t = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in } }\n"
        "  func stop() { t?.invalidate() }\n"
        "}\n"
    )
    assert scan_text(code) == [], scan_text(code)


def _selftest_suffix_gate() -> None:
    leaky = "Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }\n"
    balanced = "let t = Timer.scheduledTimer { _ in }\nt.invalidate()\n"
    assert scan_text(leaky) == [("timer", 1, 0)]
    assert scan_text(balanced) == []
    swift = Path("A.swift")
    markdown = Path("A.md")
    assert swift.suffix in _SUFFIX_SET and markdown.suffix not in _SUFFIX_SET


def _selftest_run(tmp_prefix: str = "ubs_core_regex_swift_") -> None:
    import tempfile

    leaky = "class A { func f() { FileHandle(forReadingFrom: url) } }\n"
    balanced = "class A { func f() { let h = FileHandle(forReadingFrom: url); h.close() } }\n"
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "A.swift"
        target.write_text(leaky, encoding="utf-8")
        findings = list(run(RunContext(lang="swift", files=[target])))
        assert len(findings) == 1, findings
        assert findings[0]["rule"] == "swift.regex.file_handle"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["message"] == "acquire=1 cleanup=0"
        target.write_text(balanced, encoding="utf-8")
        assert list(run(RunContext(lang="swift", files=[target]))) == []


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("timer_positive", _selftest_timer_positive),
    ("invalidated_suppression", _selftest_invalidated_suppression),
    ("suffix_gate", _selftest_suffix_gate),
    ("run_finds_imbalance", _selftest_run),
)

register(Analyzer(layer="regex", lang="swift", name="regex_swift", run=run, selftests=SELF_TESTS))
