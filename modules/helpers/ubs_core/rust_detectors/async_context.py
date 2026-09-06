"""ubs_core.rust_detectors.async_context — blocking calls in async fns (bead 0xjg.7).

Port of rust_async_context_matches (modules/ubs-rust.sh 1270-1415): flags
mode-selected blocking patterns (thread::sleep / std::fs calls / block_on /
thread::spawn) inside `async fn` bodies. The legacy UBS_RUST_FILE_LIST/rglob
iteration is replaced by the caller's `files` argument (the heredoc had no
.resolve(); entries keep their given spelling), and the legacy skip-dir list
is documentation-only.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

MODES = ("sleep", "fs", "block_on", "thread_spawn")
MODE_RULE_IDS = {
    "sleep": "rust.async.sleep-in-async",
    "fs": "rust.async.fs-in-async",
    "block_on": "rust.async.block-on-in-async",
    "thread_spawn": "rust.async.thread-spawn-in-async",
}
MODE_CATEGORIES = {
    "sleep": 3,
    "fs": 3,
    "block_on": 3,
    "thread_spawn": 3,
}
MODE_TITLES = {
    "sleep": "thread::sleep in async",
    "fs": "Blocking std::fs in async code",
    "block_on": "block_on within async function",
    "thread_spawn": "std::thread::spawn inside async fn",
}
MODE_SEVERITIES = {
    "sleep": "warning",
    "fs": "info",
    "block_on": "warning",
    "thread_spawn": "warning",
}
MODE_DESCRIPTIONS = {
    "sleep": "",
    "fs": "",
    "block_on": "",
    "thread_spawn": "",
}

patterns = {
    "sleep": re.compile(r"\b(?:std::)?thread::sleep\s*\("),
    "fs": re.compile(r"\b(?:std::)?fs::(?:read|read_to_string|write|rename|copy|remove_file)\s*\("),
    "block_on": re.compile(r"\b(?:futures::executor::block_on|tokio::runtime::Runtime::block_on)\s*\("),
    "thread_spawn": re.compile(r"\b(?:std::)?thread::spawn\s*\("),
}


def mask_comments_and_strings(text: str) -> str:
    chars = list(text)
    i = 0
    n = len(chars)
    state = "code"
    quote = ""
    while i < n:
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                while i < n and chars[i] != "\n":
                    chars[i] = " "
                    i += 1
                continue
            if ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block"
                continue
            if ch == '"':
                quote = ch
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
            if ch == quote:
                chars[i] = " "
                i += 1
                state = "code"
                continue
            if ch != "\n":
                chars[i] = " "
        i += 1
    return "".join(chars)


def find_matching_brace(text: str, open_index: int) -> int:
    depth = 0
    for idx in range(open_index, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


async_fn = re.compile(r"\basync\s+fn\s+[A-Za-z_][A-Za-z0-9_]*[^{;]*\{", re.MULTILINE)


def find(files: Sequence[Path], mode: str) -> Iterable[tuple]:
    pattern = patterns[mode]
    seen = set()
    for path in files:
        if path.suffix != ".rs":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        masked = mask_comments_and_strings(text)
        lines = text.splitlines()
        for fn_match in async_fn.finditer(masked):
            open_brace = masked.find("{", fn_match.start())
            if open_brace < 0:
                continue
            close_brace = find_matching_brace(masked, open_brace)
            if close_brace < 0:
                continue
            body = masked[open_brace:close_brace + 1]
            for hit in pattern.finditer(body):
                offset = open_brace + hit.start()
                line = line_number(masked, offset)
                key = (str(path), line, mode)
                if key in seen:
                    continue
                seen.add(key)
                code = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                if "ubs:ignore" in code:
                    continue
                yield path, line, 1, code


if __name__ == "__main__":
    import sys

    args = sys.argv[1:]
    mode = MODES[0]
    if args and args[0] == "--mode":
        mode = args[1]
        args = args[2:]
    root_files = [Path(p) for p in args]
    for path, line, col, code in find(root_files, mode):
        print(f"{path}:{line}:{code}")
