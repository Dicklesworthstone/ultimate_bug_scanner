"""ubs_core.rust_detectors.cors_credential — cat 8 CORS credential policy (bead 0xjg.7).

Port of rust_cors_credential_matches (modules/ubs-rust.sh 4724-4978):
flags CORS contexts that combine credentials
(Access-Control-Allow-Credentials / allow_credentials(true) /
supports_credentials) with a wildcard/any origin (`*` Allow-Origin header,
allow_origin(Any), allow_any_origin(), allowed_origin_fn returning true)
or a reflected request Origin (directly or via a local assigned from an
Origin header source), unless the enclosing fn scope shows a safe-origin
guard (allowlist naming plus a reject/Err/bail!/ensure! escape).
Taint tracking of origin-carrying locals is per-file.

Legacy outcome:

    print_finding critical <count> "Credentialed wildcard/reflected CORS" ...

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

RULE_ID = "rust.security.cors-credentials"
CATEGORY = 8
TITLE = "Credentialed wildcard/reflected CORS"
SEVERITY = "critical"
DESCRIPTION = (
    "Use an explicit trusted origin allow-list and emit Vary: Origin "
    "when Access-Control-Allow-Credentials is true"
)

credential_re = re.compile(
    r'Access-Control-Allow-Credentials|ACCESS_CONTROL_ALLOW_CREDENTIALS|'
    r'\ballow_credentials\s*\(\s*true\s*\)|\bsupports_credentials\s*\(',
    re.IGNORECASE,
)
wildcard_re = re.compile(
    r'\ballow_origin\s*\(\s*Any\s*\)|\ballow_any_origin\s*\(|'
    r'\ballowed_origin_fn\s*\([^)]*\btrue\b|'
    r'Access-Control-Allow-Origin[\s\S]{0,240}["\']\*["\']|'
    r'ACCESS_CONTROL_ALLOW_ORIGIN[\s\S]{0,240}(?:from_static|from_str)?\s*\(\s*["\']\*["\']',
    re.IGNORECASE | re.DOTALL,
)
origin_source_re = re.compile(
    r'\b(?:req|request|headers|header_map)\s*\.\s*(?:headers\s*\(\s*\)\s*\.)?get\s*\(\s*["\']origin["\']\s*\)|'
    r'\b(?:req|request)\s*\.\s*headers\s*\(\s*\)\s*\.\s*get\s*\(\s*header::ORIGIN\s*\)|'
    r'\b(?:ORIGIN|header::ORIGIN)\b|'
    r'\b(?:origin_header|request_origin|origin)\b',
    re.IGNORECASE,
)
origin_sink_re = re.compile(
    r'Access-Control-Allow-Origin|ACCESS_CONTROL_ALLOW_ORIGIN|'
    r'\bappend_header\s*\(\s*\(\s*["\']Access-Control-Allow-Origin["\']|'
    r'\binsert_header\s*\(\s*\(\s*["\']Access-Control-Allow-Origin["\']',
    re.IGNORECASE,
)
assign_re = re.compile(
    r'^\s*(?:let\s+(?:mut\s+)?|const\s+|static\s+)?'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(?P<rhs>.+)$'
)
safe_re = re.compile(
    r'\b(?:is_allowed_origin|is_trusted_origin|validate_origin|validated_origin|'
    r'allowed_origins|trusted_origins|origin_allowlist|cors_allowlist|'
    r'allowlisted_origin|safe_origin)\b',
    re.IGNORECASE,
)
reject_re = re.compile(r'\b(?:return|return\s+Err|Err\s*\(|bail!\s*\(|ensure!\s*\()\b')


def strip_line_comments(line: str) -> str:
    out = []
    quote = ""
    raw_hashes = None
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if raw_hashes is not None:
            out.append(ch)
            if ch == '"' and line.startswith("#" * raw_hashes, i + 1):
                out.extend("#" * raw_hashes)
                i += raw_hashes + 1
                raw_hashes = None
                continue
            i += 1
            continue
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch == "r":
            j = i + 1
            while j < len(line) and line[j] == "#":
                j += 1
            if j < len(line) and line[j] == '"':
                raw_hashes = j - i - 1
                out.extend(line[i : j + 1])
                i = j + 1
                continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def logical_statement(lines, line_no, max_lines=16):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    paren = statement.count("(") - statement.count(")")
    brace = statement.count("{") - statement.count("}")
    has_end = ";" in statement or "{" in statement or "}" in statement
    lookahead = idx + 1
    while (paren > 0 or brace > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + max_lines:
        nxt = strip_line_comments(lines[lookahead]).strip()
        statement += " " + nxt
        paren += nxt.count("(") - nxt.count(")")
        brace += nxt.count("{") - nxt.count("}")
        has_end = has_end or ";" in nxt or "{" in nxt or "}" in nxt
        lookahead += 1
    return statement


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and "ubs:ignore" in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and "ubs:ignore" in lines[idx - 1]
    )


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""


def context(lines, line_no, before=18, after=18):
    idx = line_no - 1
    start = max(0, idx - before)
    end = min(len(lines), idx + after + 1)
    return "\n".join(strip_line_comments(line) for line in lines[start:end])


def cors_context(lines, line_no, before=24, after=24):
    idx = line_no - 1
    start = max(0, idx - before)
    end = min(len(lines), idx + after + 1)
    boundary_re = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*\b')
    for pos in range(idx - 1, start - 1, -1):
        if boundary_re.search(strip_line_comments(lines[pos])):
            start = pos
            break
    for pos in range(idx + 1, end):
        if boundary_re.search(strip_line_comments(lines[pos])):
            end = pos
            break
    return "\n".join(strip_line_comments(line) for line in lines[start:end])


def refs_in_text(text, refs):
    return [name for name in refs if re.search(rf'\b{re.escape(name)}\b', text)]


def has_safe_origin_guard(text, refs):
    if not refs_in_text(text, refs):
        return False
    return bool(safe_re.search(text) and reject_re.search(text))


def analyze(path: Path, issues):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if not credential_re.search(text):
        return
    lines = text.splitlines()
    tainted_origins = {}
    seen = set()
    for line_no, _ in enumerate(lines, start=1):
        if has_ignore(lines, line_no):
            continue
        raw_line = strip_line_comments(lines[line_no - 1]).strip()
        if not raw_line:
            continue
        statement = logical_statement(lines, line_no).strip()
        if not statement:
            continue
        assign = assign_re.match(statement)
        if assign:
            name = assign.group("lhs")
            rhs = assign.group("rhs")
            if origin_source_re.search(rhs) and not safe_re.search(rhs):
                tainted_origins[name] = line_no
            elif safe_re.search(rhs):
                tainted_origins.pop(name, None)

        statement_has_policy = (
            credential_re.search(raw_line)
            or wildcard_re.search(raw_line)
            or origin_sink_re.search(raw_line)
        )
        if not statement_has_policy:
            continue

        window = cors_context(lines, line_no)
        has_credentials = bool(credential_re.search(statement) or credential_re.search(window))
        if not has_credentials:
            continue

        reason = ""
        if wildcard_re.search(statement) or wildcard_re.search(window):
            reason = "credentials enabled with wildcard/any origin"
        elif origin_sink_re.search(statement) or origin_sink_re.search(window):
            refs = refs_in_text(statement + "\n" + window, tainted_origins)
            direct_origin = origin_source_re.search(statement) or origin_source_re.search(window)
            if refs or direct_origin:
                if has_safe_origin_guard(window, refs or ["origin", "request_origin", "origin_header"]):
                    continue
                reason = "credentials enabled with reflected request Origin"
        if not reason:
            continue
        key = (path, line_no, reason)
        if key in seen:
            continue
        seen.add(key)
        issues.append((path, line_no, f"{source_line(lines, line_no)}  [{reason}]"))


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
