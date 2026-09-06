"""ubs_core.rust_detectors.unbounded_request_body — cat 8 unbounded request bodies (bead 0xjg.7).

Port of rust_unbounded_request_body_matches (modules/ubs-rust.sh 4473-4682):
flags request bodies buffered without an explicit byte limit — `to_bytes`
calls with fewer than two top-level arguments or with a
`usize::MAX`/`u64::MAX`/`u32::MAX` limit, or `.collect().await` results
piped into `.to_bytes` — unless a limiting mechanism (DefaultBodyLimit,
RequestBodyLimitLayer, http_body_util::Limited, ContentLengthLimit,
tower_http::limit) or a content-length comparison guard appears in the
surrounding context (35 lines before / 10 after).

Legacy outcome:

    print_finding warning <count> "Request body read without explicit byte limit" ...

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

RULE_ID = "rust.security.request-body-limit"
CATEGORY = 8
TITLE = "Request body read without explicit byte limit"
SEVERITY = "warning"
DESCRIPTION = (
    "Use DefaultBodyLimit::max, RequestBodyLimitLayer, http_body_util::Limited, "
    "or axum::body::to_bytes(body, limit) before buffering request bodies"
)

TO_BYTES_RE = re.compile(r"\b(?:(?:hyper|axum)::)?body::to_bytes\s*\(")
UNSAFE_LIMIT_RE = re.compile(r"\b(?:(?:std::)?usize|u64|u32)::MAX\b")
COLLECT_BYTES_RE = re.compile(r"\.collect\s*\(\)\s*\.await(?:\?|\.[A-Za-z_][A-Za-z0-9_]*\(\))?[^;\n]*\.to_bytes\s*\(")
SAFE_CONTEXT_RE = re.compile(
    r"\b(?:DefaultBodyLimit::max|RequestBodyLimitLayer::new|RequestBodyLimit|"
    r"ContentLengthLimit|tower_http::limit|http_body_util::Limited|Limited::new|"
    r"ContentLengthLimitLayer)\b"
)
CONTENT_LENGTH_GUARD_RE = re.compile(r"\b(?:CONTENT_LENGTH|content_length|content-length)\b[\s\S]{0,240}\b(?:>|>=)\b")


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
                    end = n if end == -1 else end + len(close)
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


def statement_from(masked_lines, idx):
    statement = masked_lines[idx].strip()
    balance = statement.count("(") + statement.count("{") - statement.count(")") - statement.count("}")
    lookahead = idx + 1
    while balance > 0 and lookahead < len(masked_lines) and lookahead < idx + 12:
        nxt = masked_lines[lookahead].strip()
        statement += " " + nxt
        balance += nxt.count("(") + nxt.count("{") - nxt.count(")") - nxt.count("}")
        lookahead += 1
    return statement


def call_args(statement, marker="to_bytes"):
    start = statement.find(marker + "(")
    if start == -1:
        return ""
    pos = start + len(marker) + 1
    depth = 1
    end = pos
    while end < len(statement):
        ch = statement[end]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return statement[pos:end]
        end += 1
    return statement[pos:]


def top_level_arg_count(args):
    if not args.strip():
        return 0
    depth = 0
    count = 1
    for ch in args:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            count += 1
    return count


def source_line(lines, idx):
    return lines[idx].strip().replace("\t", " ")


def context_around(original_lines, idx):
    start = max(0, idx - 35)
    end = min(len(original_lines), idx + 10)
    return "\n".join(original_lines[start:end])


def has_ignore(lines, idx):
    start = max(0, idx - 2)
    return any("ubs:ignore" in lines[pos] for pos in range(start, idx + 1))


def context_is_limited(context: str) -> bool:
    return bool(SAFE_CONTEXT_RE.search(context) or CONTENT_LENGTH_GUARD_RE.search(context))


def unbounded_to_bytes(statement: str) -> bool:
    if not TO_BYTES_RE.search(statement):
        return False
    args = call_args(statement)
    argc = top_level_arg_count(args)
    return argc < 2 or bool(UNSAFE_LIMIT_RE.search(args))


def analyze(path: Path, issues):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    masked_lines = mask_comments_and_strings(text).splitlines()
    lines = text.splitlines()
    seen = set()
    for idx, masked in enumerate(masked_lines):
        if has_ignore(lines, idx):
            continue
        stripped = masked.strip()
        if not stripped:
            continue
        if "to_bytes" not in stripped and ".collect" not in stripped:
            continue
        statement = statement_from(masked_lines, idx)
        if not (unbounded_to_bytes(statement) or COLLECT_BYTES_RE.search(statement)):
            continue
        context = context_around(lines, idx)
        if context_is_limited(context):
            continue
        key = (str(path), idx + 1)
        if key in seen:
            continue
        seen.add(key)
        issues.append((path, idx + 1, source_line(lines, idx)))


def find(files: Sequence[Path]) -> Iterator[tuple[Path, int, int, str]]:
    for path in files:
        results: list[tuple[Path, int, str]] = []
        analyze(path, results)
        for issue_path, line_no, code in results:
            yield (issue_path, line_no, 1, code)


if __name__ == "__main__":
    import sys

    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
