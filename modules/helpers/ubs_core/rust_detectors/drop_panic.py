"""ubs_core.rust_detectors.drop_panic — panics inside Drop impls (bead 0xjg.7).

Port of rust_drop_panic_matches (modules/ubs-rust.sh 1722-1888): flags
panic!/unreachable!/todo!/unimplemented!/assert*!/unwrap/expect calls inside
`fn drop(&mut self)` bodies of `impl Drop for ...` blocks. The legacy
UBS_RUST_FILE_LIST/rglob iteration is replaced by the caller's `files`
argument (the heredoc had no .resolve(); entries keep their given spelling),
and the legacy skip-dir list is documentation-only.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "rust.panic.drop"
CATEGORY = 21
TITLE = "Potential panics inside Drop implementations"
SEVERITY = "warning"
DESCRIPTION = (
    "Panics during Drop + unwinding can abort; avoid unwrap/expect/panic in destructors"
)

impl_drop = re.compile(r"\bimpl\b[^{};]*\bDrop\b[^{};]*\bfor\b[^{;]*\{", re.MULTILINE)
drop_fn = re.compile(r"\bfn\s+drop\s*\(\s*&mut\s+self\s*\)\s*(?:->[^{]+)?\{", re.MULTILINE)
panic_surface = re.compile(
    r"\b(?:panic|unreachable|todo|unimplemented|assert|assert_eq|assert_ne)!\s*\(|\.(?:unwrap|expect)\s*\("
)


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


def find(files: Sequence[Path]) -> Iterable[tuple]:
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
        for impl_match in impl_drop.finditer(masked):
            impl_open = masked.rfind("{", impl_match.start(), impl_match.end())
            if impl_open < 0:
                continue
            impl_close = find_matching_brace(masked, impl_open)
            if impl_close < 0:
                continue
            impl_body = masked[impl_open:impl_close + 1]
            for fn_match in drop_fn.finditer(impl_body):
                fn_open = impl_open + impl_body.find("{", fn_match.start(), fn_match.end())
                if fn_open < impl_open:
                    continue
                fn_close = find_matching_brace(masked, fn_open)
                if fn_close < 0 or fn_close > impl_close:
                    continue
                drop_body = masked[fn_open:fn_close + 1]
                for hit in panic_surface.finditer(drop_body):
                    offset = fn_open + hit.start()
                    line = line_number(masked, offset)
                    key = (str(path), line, hit.group(0))
                    if key in seen:
                        continue
                    seen.add(key)
                    code = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                    if "ubs:ignore" in code:
                        continue
                    yield path, line, 1, code


if __name__ == "__main__":
    import sys

    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
