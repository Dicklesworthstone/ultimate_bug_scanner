"""ubs_core.rust_detectors.path_traversal — category 8 security (bead 0xjg.7).

Port of rust_path_traversal_matches (modules/ubs-rust.sh 1930-2103): flags
`.join()`/`.push()` calls on path-ish receivers (path/dir/root/base/... named
variables) with untrusted-looking segment arguments (user/input/upload/...
named variables). GH #96 receiver-type awareness: let-bindings whose declared
type or initializer is a known collection (Vec/VecDeque/HashSet/.../String)
are exempt so `.push` on a plain collection is not a filesystem join.
`ubs:ignore` on the flagged line suppresses a hit.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

RULE_ID = "rust.security.path-traversal"
CATEGORY = 8
TITLE = "Path join/push with untrusted-looking segment"
SEVERITY = "warning"
DESCRIPTION = (
    "Reject absolute paths and '..' components; canonicalize and verify the "
    "result stays under the intended root"
)

# Documentation only: the orchestrator already passes the filtered file list
# (legacy rglob fallback applied this skip list).
skip_dirs = {".git", "target", ".cargo", "node_modules"}
pathish = re.compile(r"(?:^|_|\.)((?:path|dir|root|base|folder|upload|download|dest|target|tmp|temp|cache|out)s?)(?:$|_|\.)")
untrusted = re.compile(r"(?:^|_)(?:user|input|upload|file|filename|path|rel|relative|request|req|param|name|key|entry|member|archive)(?:$|_)")
call = re.compile(
    r"\b(?P<recv>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r"\s*\.\s*(?P<method>join|push)\s*\(\s*&?\s*(?P<arg>[A-Za-z_][A-Za-z0-9_]*)"
)
# GH #96: `.push` on a collection (Vec<PathBuf> named `paths`, String named
# `out`, ...) is not a filesystem join, no matter what the variable is called.
# Track let-bindings whose declared type or initializer is a known collection
# and exempt their `.push` calls (receiver-type awareness).
let_binding = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?::\s*(?P<ty>[^=;]+?)\s*)?=\s*(?P<init>[^;]{0,160})"
)
collection_type = re.compile(
    r"^\s*&?\s*(?:mut\s+)?(?:std::(?:vec::|collections::|string::)?)?"
    r"(?:Vec|VecDeque|HashSet|BTreeSet|BinaryHeap|SmallVec|String)\b"
)
collection_init = re.compile(
    r"^\s*(?:std::(?:vec::|collections::|string::)?)?"
    r"(?:(?:Vec|VecDeque|HashSet|BTreeSet|BinaryHeap|SmallVec|String)\s*(?:::<[^;]*?>)?\s*::\s*"
    r"(?:new|with_capacity|from|default)\b|vec!|String::new)"
)


def collection_vars(masked: str):
    found = set()
    for m in let_binding.finditer(masked):
        ty = m.group("ty") or ""
        init = m.group("init") or ""
        if (ty and collection_type.search(ty)) or collection_init.search(init):
            found.add(m.group("var"))
    return found


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


def find(files) -> Iterator[tuple[Path, int, int, str]]:
    """Yield (path, line, col, code) per legacy deduped finding, in legacy
    order. `files` is the ordered list of Path entries to scan."""
    seen = set()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        masked = mask_comments_and_strings(text)
        lines = text.splitlines()
        collections = collection_vars(masked)
        for hit in call.finditer(masked):
            recv = hit.group("recv").lower()
            arg = hit.group("arg").lower()
            if not pathish.search(recv):
                continue
            if not untrusted.search(arg):
                continue
            if hit.group("method") == "push" and hit.group("recv") in collections:
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
