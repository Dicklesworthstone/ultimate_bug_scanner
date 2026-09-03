"""ubs_core.analyzers.lifecycle_swift — Swift resource lifecycle analysis (bead A2).

Logic moved verbatim from modules/helpers/resource_lifecycle_swift.py, which remains
as a thin entrypoint. Also exposes a structured `run(ctx)` for the
`python3 -m ubs_core` CLI.
"""
import re
import sys
from pathlib import Path
from typing import Iterable
import re
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register

SKIP_DIRS = {".git", ".hg", ".svn", "build", "DerivedData", ".swiftpm", ".idea", "node_modules"}

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"

ASSIGNED_RULES: tuple[tuple[str, str, re.Pattern[str], tuple[re.Pattern[str], ...]], ...] = (
    (
        "timer",
        "Timer is never invalidated",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*(?:try[!?]?\s*)?(?:Timer\.scheduledTimer|Timer\.publish\s*\()"),
        (re.compile(r"\.invalidate\s*\("),),
    ),
    (
        "urlsession_task",
        "URLSession task is never resumed or cancelled",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*(?:try[!?]?\s*)?[^=\n;]*\.(?:dataTask|uploadTask|downloadTask)\s*\("),
        (re.compile(r"\.(?:resume|cancel)\s*\("),),
    ),
    (
        "notification_token",
        "NotificationCenter observer token is never removed",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*NotificationCenter\.default\.addObserver\s*\("),
        (re.compile(r"NotificationCenter\.default\.removeObserver\s*\("), re.compile(r"\.removeObserver\s*\(")),
    ),
    (
        "file_handle",
        "FileHandle is never closed",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*(?:try[!?]?\s*)?FileHandle\s*\(\s*for(?:Reading|Writing|Updating)(?:From|To|AtPath)\s*:"),
        (re.compile(r"\.(?:close|closeFile)\s*\("),),
    ),
    (
        "combine_sink",
        "Combine sink result is neither stored nor cancelled",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*.*?\.sink\s*\(", re.MULTILINE),
        (re.compile(r"\.store\s*\(\s*in:\s*&"), re.compile(r"\.cancel\s*\(")),
    ),
    (
        "dispatch_source",
        "DispatchSource is never resumed or cancelled",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*DispatchSource\.(?:makeTimerSource|makeFileSystemObjectSource|makeReadSource|makeWriteSource)\s*\("),
        (re.compile(r"\.(?:resume|cancel)\s*\("),),
    ),
    (
        "cadisplaylink",
        "CADisplayLink is never invalidated",
        re.compile(rf"\b(?:let|var)\s+({IDENT})\s*=\s*CADisplayLink\s*\("),
        (re.compile(r"\.invalidate\s*\("),),
    ),
)

KVO_RULE = (
    "kvo_observer",
    "KVO observer is added without a matching removeObserver",
    re.compile(r"\baddObserver\s*\([^)]*forKeyPath:"),
    re.compile(r"\bremoveObserver\s*\([^)]*forKeyPath:"),
)

SWIFTISH_SUFFIXES = {".swift", ".m", ".mm"}

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


def iter_swiftish_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in SWIFTISH_SUFFIXES and not any(part in SKIP_DIRS for part in root.parts):
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in SWIFTISH_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def strip_comments_and_strings(text: str) -> str:
    result: list[str] = []
    i = 0
    n = len(text)
    in_line = False
    in_block = False
    in_string = False
    escaped = False
    quote = ""

    def mask_char(ch: str) -> str:
        return "\n" if ch == "\n" else " "

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line:
            result.append(mask_char(ch))
            if ch == "\n":
                in_line = False
            i += 1
            continue

        if in_block:
            result.append(mask_char(ch))
            if ch == "*" and nxt == "/":
                result.append(" ")
                in_block = False
                i += 2
            else:
                i += 1
            continue

        if in_string:
            result.append(mask_char(ch))
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_string = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            result.extend("  ")
            in_line = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            result.extend("  ")
            in_block = True
            i += 2
            continue

        if ch == '"':
            result.append(mask_char(ch))
            in_string = True
            quote = ch
            i += 1
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def line_col(text: str, pos: int) -> tuple[int, int]:
    line = text.count("\n", 0, pos) + 1
    last_newline = text.rfind("\n", 0, pos)
    col = pos + 1 if last_newline == -1 else pos - last_newline
    return line, col


def rel_to(base: Path, path: Path) -> Path:
    try:
        return path.relative_to(base)
    except ValueError:
        return path


def search_release(name: str, patterns: tuple[re.Pattern[str], ...], text: str, start: int) -> bool:
    for pattern in patterns:
        if pattern.search(text, start):
            return True
        scoped = re.compile(rf"\b{re.escape(name)}{pattern.pattern}")
        if scoped.search(text, start):
            return True
    return False


def scan_text(path: Path, text: str, base: Path) -> list[tuple[str, str, str, int, int]]:
    """Return (kind, message, rel, line, col) findings for one file's text."""
    code = strip_comments_and_strings(text)
    rel = str(rel_to(base, path))
    found: list[tuple[str, str, str, int, int]] = []
    seen: set[tuple[str, str, str]] = set()

    def emit(pos: int, kind: str, message: str) -> None:
        line, col = line_col(text, pos)
        issue = (f"{rel}:{line}:{col}", kind, message)
        if issue not in seen:
            seen.add(issue)
            found.append((kind, message, rel, line, col))

    for kind, message, acquire, release_patterns in ASSIGNED_RULES:
        for match in acquire.finditer(code):
            name = match.group(1)
            if search_release(name, release_patterns, code, match.end()):
def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: resource_lifecycle_swift.py <project_dir>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    for loc, kind, message in collect_issues(root):
        print(f"{loc}\t{kind}\t{message}")
    return 0
        for match in kvo_acquire.finditer(code):
            emit(match.start(), kvo_kind, kvo_message)

    return found


def collect_issues(root: Path) -> list[tuple[str, str, str]]:
    issues: list[tuple[str, str, str]] = []
    base = root if root.is_dir() else root.parent

    for path in iter_swiftish_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for kind, message, rel, line, col in scan_text(path, text, base):
            issues.append((f"{rel}:{line}:{col}", kind, message))

    return issues


def main() -> int:
    import sys

    if len(sys.argv) != 2:
        print("usage: resource_lifecycle_swift.py <project_dir>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    if not root.exists():
        return 0
    for loc, kind, message in collect_issues(root):
        print(f"{loc}\t{kind}\t{message}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in SWIFTISH_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for kind, message, rel, line, col in scan_text(path, text, cwd):
            yield {
                "rule": f"swift.lifecycle.{kind}",
                "path": rel,
                "line": line,
                "col": col,
                "layer": "lifecycle",
                "lang": "swift",
                "severity": _SEVERITY[kind],
                "message": message,
            }


def _selftest_timer_positive() -> None:
    code = (
        "class A {\n"
        "  // timer.invalidate() mentioned in a comment must not mask the leak\n"
        "  let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }\n"
        "  let leaky = Timer.publish(every: 2, on: .main, in: .common).autoconnect()\n"
        "}\n"
    )
    issues = scan_text(Path("A.swift"), code, Path("."))
    kinds = [kind for kind, _, _, _, _ in issues]
    assert kinds == ["timer", "timer"], kinds
    assert "(timer)" in issues[0][1] and "(leaky)" in issues[1][1]
    assert issues[0][3] == 3 and issues[1][3] == 4, issues


def _selftest_invalidated_suppression() -> None:
    code = (
        "class A {\n"
        '  let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }\n'
        "  func stop() { timer.invalidate() }\n"
        '  let s = "let fake = Timer.scheduledTimer(x)"\n'
        "}\n"
    )
    assert scan_text(Path("A.swift"), code, Path(".")) == []


def _selftest_kvo_suppression() -> None:
    leaky = 'obj.addObserver(self, forKeyPath: "state", options: [], context: nil)\n'
    issues = scan_text(Path("A.swift"), leaky, Path("."))
    assert [kind for kind, _, _, _, _ in issues] == ["kvo_observer"], issues
    cleaned = leaky + 'func deinit2() { obj.removeObserver(self, forKeyPath: "state") }\n'
    assert scan_text(Path("A.swift"), cleaned, Path(".")) == []


def _selftest_run(tmp_prefix: str = "ubs_core_lifecycle_swift_") -> None:
    import tempfile

    code = (
        "import Foundation\n"
        "class A {\n"
        "  let handle = try FileHandle(forReadingFrom: url)\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "A.swift"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="swift", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "swift.lifecycle.file_handle"
    assert findings[0]["line"] == 3
    assert findings[0]["col"] == 15
    assert findings[0]["severity"] == "critical"


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("timer_positive", _selftest_timer_positive),
    ("invalidated_suppression", _selftest_invalidated_suppression),
    ("kvo_suppression", _selftest_kvo_suppression),
    ("run_finds_leak", _selftest_run),
)

register(Analyzer(layer="lifecycle", lang="swift", name="lifecycle_swift", run=run, selftests=SELF_TESTS))
