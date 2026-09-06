"""ubs_core.csharp_detectors — legacy heredoc detector ports (bead 0xjg.12).

Shared helpers for the verbatim ports of the ubs-csharp.sh cat-8 python
heredocs (run_archive_extraction_checks / run_response_header_injection_checks /
run_request_outbound_url_checks / run_security_randomness_checks, 1406-2880).
Statement joining, comment stripping, and ubs:ignore placement are
byte-faithful to the heredocs; the os.walk/NUL-filelist loader is replaced by
iteration over ``RunContext.files`` (the caller's file list).
"""
from __future__ import annotations

from pathlib import Path

MARKER = "ubs:ignore"


def strip_line_comments(line: str) -> str:
    """Heredoc line-comment stripper (quote-aware, `//` only)."""
    out = []
    quote = ""
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
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
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def strip_line_comments_block(line: str) -> str:
    """security_randomness stripper — additionally skips /* */ ranges."""
    out = []
    quote = ""
    escape = False
    i = 0
    while i < len(line):
        ch = line[i]
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
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < len(line):
            nxt = line[i + 1]
            if nxt == "/":
                break
            if nxt == "*":
                end = line.find("*/", i + 2)
                if end == -1:
                    break
                i = end + 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def has_ignore(lines, line_no):
    """Heredoc marker placement: current line or the line above."""
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and MARKER in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]
    )


def logical_statement(lines, line_no):
    """Paren/end-aware statement joiner (path-traversal/open-redirect/outbound)."""
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    paren_balance = statement.count("(") - statement.count(")")
    has_end = ";" in statement or "{" in statement or "}" in statement
    lookahead = idx + 1
    while (paren_balance > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 10:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += " " + next_line
        paren_balance += next_line.count("(") - next_line.count(")")
        has_end = has_end or ";" in next_line or "{" in next_line or "}" in next_line
        lookahead += 1
    return statement


def logical_statement_brackets(lines, line_no):
    """header_injection joiner — also balances [] and {} (heredoc 2212-2230)."""
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    paren_balance = statement.count("(") - statement.count(")")
    bracket_balance = statement.count("[") - statement.count("]")
    brace_balance = statement.count("{") - statement.count("}")
    has_end = ";" in statement or "{" in statement or "}" in statement
    lookahead = idx + 1
    while (
        paren_balance > 0 or bracket_balance > 0 or brace_balance > 0 or not has_end
    ) and lookahead < len(lines) and lookahead < idx + 10:
        next_line = strip_line_comments(lines[lookahead]).strip()
        statement += " " + next_line
        paren_balance += next_line.count("(") - next_line.count(")")
        bracket_balance += next_line.count("[") - next_line.count("]")
        brace_balance += next_line.count("{") - next_line.count("}")
        has_end = has_end or ";" in next_line or "{" in next_line or "}" in next_line
        lookahead += 1
    return statement


def logical_statement_randomness(lines, start_idx):
    """security_randomness joiner — first statement end within 9 lines (2732-2743)."""
    pieces = []
    paren_balance = 0
    for raw in lines[start_idx - 1:min(len(lines), start_idx + 8)]:
        line = strip_line_comments_block(raw).strip()
        if not line:
            continue
        pieces.append(line)
        paren_balance += line.count("(") - line.count(")")
        if paren_balance <= 0 and (";" in line or "{" in line or "}" in line or "=>" in line):
            break
    return " ".join(pieces)


def context_around(lines, line_no):
    """archive_extraction context window (1500-1503)."""
    start = max(0, line_no - 10)
    end = min(len(lines), line_no + 12)
    return "\n".join(strip_line_comments(line) for line in lines[start:end])


def relpath(path: Path, base_dir: Path) -> str:
    try:
        return str(path.resolve().relative_to(base_dir))
    except ValueError:
        return str(path)


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ""
