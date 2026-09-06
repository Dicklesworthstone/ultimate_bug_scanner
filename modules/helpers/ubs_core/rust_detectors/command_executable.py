"""ubs_core.rust_detectors.command_executable — cat 8 command executable source (bead 0xjg.7).

Port of rust_command_executable_matches (modules/ubs-rust.sh 5020-5170):
flags `Command::new(<expr>)` calls whose executable expression looks
untrusted — any dotted-path segment matching the untrusted-name pattern
(user/input/cmd/command/program/exe/binary/tool/shell/path/request/
req/param/name/key), after stripping as_str/as_ref/to_string/
into_string adapters. Comments and strings are masked before matching;
`ubs:ignore` on the hit line suppresses it. The `seen` dedup key is
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

RULE_ID = "rust.security.command-executable"
CATEGORY = 8
TITLE = "Command executable from untrusted-looking value"
SEVERITY = "critical"
DESCRIPTION = (
    "Use a fixed executable allowlist; pass user data only as argv after validation"
)

identifier = r"[A-Za-z_][A-Za-z0-9_]*"
call = re.compile(
    rf"\b(?:std::process::)?Command\s*::\s*new\s*\(\s*&?\s*"
    rf"(?P<expr>{identifier}(?:\s*\.\s*{identifier})*)"
)
untrusted = re.compile(
    r"(?:^|_)(?:user|input|cmd|command|program|exe|binary|tool|shell|path|request|req|param|name|key)(?:$|_)"
)
adapter_methods = {"as_str", "as_ref", "to_string", "into_string"}


def mask_range(chars, start, end):
    for pos in range(start, min(end, len(chars))):
        if chars[pos] != "\n":
            chars[pos] = " "


def mask_comments_and_strings(text: str) -> str:
    chars = list(text)
    i = 0
    n = len(chars)
    state = "code"
    while i < n:
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                start = i
                i += 2
                while i < n and chars[i] != "\n":
                    i += 1
                mask_range(chars, start, i)
                continue
            if ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block"
                continue
            if ch == "r":
                j = i + 1
                while j < n and chars[j] == "#":
                    j += 1
                if j < n and chars[j] == '"':
                    hashes = j - i - 1
                    close = '"' + ("#" * hashes)
                    end = text.find(close, j + 1)
                    if end == -1:
                        end = n - 1
                    else:
                        end += len(close)
                    mask_range(chars, i, end)
                    i = end
                    continue
            if ch == '"':
                chars[i] = " "
                i += 1
                state = "string"
                continue
        elif state == "block":
            if ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "code"
                continue
            if ch != "\n":
                chars[i] = " "
        elif state == "string":
            if ch == "\\":
                chars[i] = " "
                if i + 1 < n and chars[i + 1] != "\n":
                    chars[i + 1] = " "
                    i += 2
                    continue
            if ch == '"':
                chars[i] = " "
                i += 1
                state = "code"
                continue
            if ch != "\n":
                chars[i] = " "
        i += 1
    return "".join(chars)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def suspicious_expr(expr: str) -> bool:
    parts = [part.strip().lower() for part in expr.split(".") if part.strip()]
    while parts and parts[-1] in adapter_methods:
        parts.pop()
    return any(untrusted.search(part) for part in parts)


def find(files: Sequence[Path]) -> Iterator[tuple[Path, int, int, str]]:
    seen = set()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        masked = mask_comments_and_strings(text)
        lines = text.splitlines()
        for hit in call.finditer(masked):
            expr = hit.group("expr")
            if not suspicious_expr(expr):
                continue
            line = line_number(masked, hit.start())
            code = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            if "ubs:ignore" in code:
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
