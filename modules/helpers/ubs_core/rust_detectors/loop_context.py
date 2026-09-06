"""ubs_core.rust_detectors.loop_context — allocations inside loops (bead 0xjg.7).

Port of rust_loop_context_matches (modules/ubs-rust.sh 1461-1677): flags
mode-selected patterns (Regex::new / .clone() / String allocations) inside
`for ... in` / `while` / `loop` bodies, with cold error-path closures and
nested async blocks masked out (GH #96). The legacy UBS_RUST_FILE_LIST/rglob
iteration is replaced by the caller's `files` argument (the heredoc had no
.resolve(); entries keep their given spelling), and the legacy skip-dir list
is documentation-only.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

MODES = ("clone", "regex_new", "string_alloc")
MODE_RULE_IDS = {
    "clone": "rust.collections.clone-in-loop",
    "regex_new": "rust.perf.regex-in-loop",
    "string_alloc": "rust.perf.string-alloc-in-loop",
}
MODE_CATEGORIES = {
    "clone": 5,
    "regex_new": 24,
    "string_alloc": 24,
}
MODE_TITLES = {
    "clone": "clone() inside loops - potential perf hit",
    "regex_new": "Regex::new compiled inside loop",
    "string_alloc": "String allocation inside loop",
}
MODE_SEVERITIES = {
    "clone": "warning",
    "regex_new": "warning",
    "string_alloc": "warning",
}
MODE_DESCRIPTIONS = {
    "regex_new": "Precompile regex once (lazy_static/once_cell) to avoid repeated compilation",
    "string_alloc": "Consider preallocating buffers, using write!, or restructuring to reduce allocations",
    "clone": "",
}

patterns = {
    "regex_new": re.compile(r"\b(?:regex::)?Regex::new\s*\("),
    "clone": re.compile(r"\.clone\s*\("),
    "string_alloc": re.compile(r"\bformat!\s*\(|\.to_string\s*\(|\.to_owned\s*\(|\bString::from\s*\("),
}

# GH #96: a `for` is only a loop when it has an `in` clause; a bare
# `for\b[^{;]*\{` also matches `impl Trait for Type {` (and `for<'a>` HRTBs),
# which turned every trait-impl body into a "loop" and flagged allocations in
# loop-free methods.
loop_start = re.compile(r"\b(?:for\b[^{;]*?\bin\b[^{;]*|while\b[^{;]*|loop\s*)\{", re.MULTILINE)

# GH #96: allocations inside cold error-path closures (map_err, ok_or_else,
# unwrap_or_else, ...) run only on the failure branch, not per iteration, and
# allocations inside nested async blocks are deferred work, not per-iteration
# hot-path cost. Mask those regions out of the loop-body search.
cold_closure = re.compile(
    r"\.\s*(?:map_err|ok_or_else|unwrap_or_else|or_else|map_or_else|expect_err)\s*\("
)
async_block = re.compile(r"\basync\s+(?:move\s+)?\{")


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


def find_matching_paren(text: str, open_index: int) -> int:
    depth = 0
    for idx in range(open_index, len(text)):
        ch = text[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def cold_ranges(masked: str):
    ranges = []
    for m in cold_closure.finditer(masked):
        open_paren = masked.find("(", m.start(), m.end() + 1)
        if open_paren < 0:
            continue
        close_paren = find_matching_paren(masked, open_paren)
        if close_paren < 0:
            continue
        ranges.append((open_paren, close_paren + 1))
    for m in async_block.finditer(masked):
        open_brace = masked.rfind("{", m.start(), m.end())
        if open_brace < 0:
            continue
        close_brace = find_matching_brace(masked, open_brace)
        if close_brace < 0:
            continue
        ranges.append((open_brace, close_brace + 1))
    return ranges


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
        excluded = cold_ranges(masked)
        for loop_match in loop_start.finditer(masked):
            open_brace = masked.rfind("{", loop_match.start(), loop_match.end())
            if open_brace < 0:
                continue
            close_brace = find_matching_brace(masked, open_brace)
            if close_brace < 0:
                continue
            body = masked[open_brace:close_brace + 1]
            for hit in pattern.finditer(body):
                offset = open_brace + hit.start()
                if any(start <= offset < end for start, end in excluded):
                    continue
                line = line_number(masked, offset)
                key = (str(path), line, mode, hit.group(0))
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
