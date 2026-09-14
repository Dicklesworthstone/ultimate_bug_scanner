"""ubs_core.rust_detectors.command_executable — cat 8 command executable source (bead 0xjg.7).

Port of rust_command_executable_matches (modules/ubs-rust.sh 5020-5170):
flags `Command::new(<expr>)` calls whose executable expression looks
untrusted — value names matching the untrusted-name pattern
(user/input/cmd/command/program/exe/binary/tool/shell/path/request/
req/param/name/key) or direct environment/argument sources. Balanced operands
preserve nested arguments while excluding namespace and callable names.
Comments and strings are masked; implicit format captures remain values.
Source suppression honors exact rule scopes and bare markers. The `seen` dedup key is
(path, line, code) across the whole file list, as in the legacy script.

Legacy outcome:

    print_finding critical <count> "Command executable from untrusted-looking value" ...

File iteration: the legacy heredoc consumed UBS_RUST_FILE_LIST when set
(GH #70) and otherwise rglob-walked the tree with skip_dirs
{.git, target, .cargo, node_modules} — kept here for documentation only.
find() iterates the orchestrator-provided `files` argument in order;
list entries were never .resolve()d.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, Sequence

from ubs_core.io import find_block_end
from ubs_core.lexer import strip_comments_and_strings
from ubs_core.suppression import SourceSuppressions

RULE_ID = "rust.security.command-executable"
CATEGORY = 8
TITLE = "Command executable from untrusted-looking value"
SEVERITY = "critical"
DESCRIPTION = (
    "Use a fixed executable allowlist; pass user data only as argv after validation"
)

identifier = r"[A-Za-z_][A-Za-z0-9_]*"
call = re.compile(
    r"\b(?:std\s*::\s*process\s*::\s*)?Command\s*::\s*new\s*\("
)
untrusted = re.compile(
    r"(?:^|_)(?:user|input|cmd|command|program|exe|binary|tool|shell|path|request|req|param|name|key)(?:$|_)"
)
input_source = re.compile(r'\b(?:std\s*::\s*)?env\s*::\s*(?:args(?:_os)?|var(?:_os)?)\s*\(')


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def suspicious_expr(expr: str) -> bool:
    masked = strip_comments_and_strings(expr, lang="rust")
    if input_source.search(masked):
        return True
    for match in re.finditer(rf'\b{identifier}\b', masked):
        before = masked[:match.start()].rstrip()
        after = masked[match.end():].lstrip()
        # Qualified type/module/callee names are not executable values. Keep
        # examining their arguments: resolve(user.command) is still untrusted.
        if before.endswith("::") or after.startswith(("::", "(", "!")):
            continue
        if untrusted.search(match.group().lower()):
            return True
    if re.search(r'\bformat\s*!', masked):
        captures = re.findall(r'(?<!\{)\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^{}]*)?\}(?!\})', expr)
        return any(untrusted.search(name.lower()) for name in captures)
    return False


def find(files: Sequence[Path]) -> Iterator[tuple[Path, int, int, str]]:
    seen = set()
    suppressions = SourceSuppressions("rust")
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        masked = strip_comments_and_strings(text, lang="rust")
        source = strip_comments_and_strings(text, lang="rust", strip_strings=False)
        suppressions.index(path, text)
        lines = text.splitlines()
        for hit in call.finditer(masked):
            closing = find_block_end(masked, hit.end() - 1, "(", ")")
            if closing < hit.end() or masked[closing] != ")":
                continue
            expr = source[hit.end():closing]
            if not suspicious_expr(expr):
                continue
            line = line_number(masked, hit.start())
            code = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            if suppressions.is_suppressed(path, line, RULE_ID):
                continue
            key = (str(path), line, code)
            if key in seen:
                continue
            seen.add(key)
            yield (path, line, 1, code)


if __name__ == "__main__":
    import sys

    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
