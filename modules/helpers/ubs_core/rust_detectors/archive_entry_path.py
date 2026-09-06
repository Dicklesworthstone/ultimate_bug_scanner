"""ubs_core.rust_detectors.archive_entry_path — category 8 security (bead 0xjg.7).

Port of rust_archive_entry_path_matches (modules/ubs-rust.sh 2145-2329): flags
`.join()`/`.push()` destinations built from archive entry names — either a
direct `<src>.name()`/`<src>.path()` argument on an archive-ish receiver
(entry/file/member/archive/zip/tar) or a join argument naming a variable that
was assigned from such an accessor. An enclosed_name/canonicalize/
starts_with/strip_prefix/components/Component::Normal/unpack_in mention in the
surrounding window suppresses the hit. `ubs:ignore` on the flagged line
suppresses a hit.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

RULE_ID = "rust.security.archive-entry-path"
CATEGORY = 8
TITLE = "Archive entry path traversal risk"
SEVERITY = "warning"
DESCRIPTION = (
    "Use zip::read::ZipFile::enclosed_name(), tar::Entry::unpack_in(), or "
    "canonicalize and verify destination containment before writing"
)

# Documentation only: the orchestrator already passes the filtered file list
# (legacy rglob fallback applied this skip list).
skip_dirs = {".git", "target", ".cargo", "node_modules"}
archive_receiver = re.compile(r"(?:entry|file|member|archive|zip|tar)", re.IGNORECASE)
direct_join = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    r"\s*\.\s*(?:join|push)\s*\(\s*&?\s*"
    r"(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:name|path)\s*\(",
    re.MULTILINE,
)
archive_assignment = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*&?\s*"
    r"(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:name|path)\s*\(",
    re.MULTILINE,
)
join_var = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    r"\s*\.\s*(?:join|push)\s*\(\s*&?\s*(?P<arg>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.MULTILINE,
)
safe_context = re.compile(
    r"\b(?:enclosed_name|canonicalize|starts_with|strip_prefix|components\s*\(|Component::Normal|unpack_in)\b"
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


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def surrounding_code(lines, line_index):
    start = max(0, line_index - 8)
    end = min(len(lines), line_index + 4)
    return "\n".join(lines[start:end])


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
        original_lines = text.splitlines()
        masked_lines = masked.splitlines()
        archive_vars = set()
        for assignment in archive_assignment.finditer(masked):
            if archive_receiver.search(assignment.group("src")):
                archive_vars.add(assignment.group("var"))

        for hit in direct_join.finditer(masked):
            if not archive_receiver.search(hit.group("src")):
                continue
            line = line_number(masked, hit.start())
            context = surrounding_code(masked_lines, line - 1)
            if safe_context.search(context):
                continue
            code = original_lines[line - 1].strip() if 0 < line <= len(original_lines) else ""
            if "ubs:ignore" in code:
                continue
            key = (str(path), line, code)
            if key in seen:
                continue
            seen.add(key)
            yield (path, line, 1, code)

        for hit in join_var.finditer(masked):
            if hit.group("arg") not in archive_vars:
                continue
            line = line_number(masked, hit.start())
            context = surrounding_code(masked_lines, line - 1)
            if safe_context.search(context):
                continue
            code = original_lines[line - 1].strip() if 0 < line <= len(original_lines) else ""
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
