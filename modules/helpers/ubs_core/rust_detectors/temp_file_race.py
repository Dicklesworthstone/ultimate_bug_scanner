"""ubs_core.rust_detectors.temp_file_race — cat 8 predictable temp-file race (bead 0xjg.7).

Port of rust_temp_file_race_matches (modules/ubs-rust.sh 5212-5419):
flags writes/creates/opens aimed at predictable temp paths — `let` locals
assigned `env::temp_dir().join(...)` (or `let mut` roots bound straight
to `temp_dir()` and later `.push()`ed) fed to `fs::write`, `File::create`,
or `OpenOptions::new()...open()`, plus direct one-statement
`write(...)`/`File::create(...)` calls on `temp_dir().join(...)`.
Suppressed when create_new(true)/NamedTempFile/tempfile::/Builder::new()/
tempdir(/persist_noclobber appears in the ±5-line context or the
statement itself. `ubs:ignore` is honored on the masked line and on the
raw source line. The `seen` dedup key is (path, line, code) across the
whole file list, as in the legacy script.

Legacy outcome:

    print_finding warning <count> "Predictable temp-file write race" ...

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

RULE_ID = "rust.security.temp-file-race"
CATEGORY = 8
TITLE = "Predictable temp-file write race"
SEVERITY = "warning"
DESCRIPTION = (
    "Use tempfile::NamedTempFile/tempfile::Builder or "
    "OpenOptions::create_new(true) with unpredictable names"
)

identifier = r"[A-Za-z_][A-Za-z0-9_]*"
temp_assignment = re.compile(
    rf"\blet\s+(?:mut\s+)?(?P<var>{identifier})\s*(?::[^=]+)?=\s*(?P<expr>[^;]*temp_dir\s*\(\s*\)[^;]*\.\s*join\s*\([^;]*)"
)
temp_push_assignment = re.compile(
    rf"\blet\s+mut\s+(?P<var>{identifier})\s*(?::[^=]+)?=\s*(?:std\s*::\s*env\s*::\s*temp_dir\s*\(\s*\)|env\s*::\s*temp_dir\s*\(\s*\)|temp_dir\s*\(\s*\))"
)
write_call = re.compile(
    rf"(?:\b(?:(?:std\s*::\s*)?fs\s*::\s*)?write\s*\(\s*&?\s*(?P<write>{identifier})\b|"
    rf"\b(?:(?:std\s*::\s*)?fs\s*::\s*)?File\s*::\s*create\s*\(\s*&?\s*(?P<create>{identifier})\b|"
    rf"\bOpenOptions\s*::\s*new\s*\(\s*\)(?P<opts>[^;]{{0,240}}?)\.\s*open\s*\(\s*&?\s*(?P<open>{identifier})\b)"
)
direct_write_call = re.compile(
    r"(?:\b(?:(?:std\s*::\s*)?fs\s*::\s*)?write\s*\(|\b(?:(?:std\s*::\s*)?fs\s*::\s*)?File\s*::\s*create\s*\()"
    r"[^;]*temp_dir\s*\(\s*\)[^;]*\.\s*join\s*\("
)
safe_context = re.compile(
    r"(?:\bcreate_new\s*\(\s*true\s*\)|\bNamedTempFile\b|\btempfile\s*::|\bBuilder\s*::\s*new\s*\(\s*\)|\btempdir\s*\(|\bpersist_noclobber\b)"
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
    start = max(0, line_index - 5)
    end = min(len(lines), line_index + 6)
    return "\n".join(lines[start:end])


def statement_from(lines, idx, max_lines=8):
    parts = []
    paren_balance = 0
    for line_idx in range(idx, min(len(lines), idx + max_lines)):
        current = lines[line_idx].strip()
        if not current:
            continue
        parts.append(current)
        paren_balance += current.count("(") - current.count(")")
        if ";" in current and paren_balance <= 0:
            break
    return " ".join(parts)


def find(files: Sequence[Path]) -> Iterator[tuple[Path, int, int, str]]:
    seen = set()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        masked = mask_comments_and_strings(text)
        original_lines = text.splitlines()
        masked_lines = masked.splitlines()
        temp_vars = set()
        temp_roots = set()
        for assignment in temp_assignment.finditer(masked):
            expr_line = line_number(masked, assignment.start())
            context = surrounding_code(masked_lines, expr_line - 1)
            if not safe_context.search(context):
                temp_vars.add(assignment.group("var"))
        for assignment in temp_push_assignment.finditer(masked):
            var = assignment.group("var")
            line = line_number(masked, assignment.start())
            context = surrounding_code(masked_lines, line - 1)
            if not safe_context.search(context):
                temp_roots.add(var)
        for var in temp_roots:
            if re.search(rf"\b{re.escape(var)}\s*\.\s*push\s*\(", masked):
                temp_vars.add(var)

        for line_idx, masked_line in enumerate(masked_lines):
            if "ubs:ignore" in masked_line:
                continue
            if not re.search(
                r"(?:\bwrite\s*\(|\b(?:(?:std\s*::\s*)?fs\s*::\s*)?File\s*::\s*create\s*\(|\bOpenOptions\s*::\s*new\s*\()",
                masked_line,
            ):
                continue
            statement = statement_from(masked_lines, line_idx)
            if not statement:
                continue
            direct = direct_write_call.search(statement)
            match = write_call.search(statement)
            var = ""
            if match:
                var = match.group("write") or match.group("create") or match.group("open") or ""
            if not direct and var not in temp_vars:
                continue
            context = surrounding_code(masked_lines, line_idx)
            if safe_context.search(context) or safe_context.search(statement):
                continue
            code = original_lines[line_idx].strip() if line_idx < len(original_lines) else ""
            if "ubs:ignore" in code:
                continue
            key = (str(path), line_idx + 1, code)
            if key in seen:
                continue
            seen.add(key)
            yield (path, line_idx + 1, 1, code)


if __name__ == "__main__":
    import sys

    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
