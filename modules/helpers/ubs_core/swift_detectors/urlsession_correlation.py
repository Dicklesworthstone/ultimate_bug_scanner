"""swift_detectors.urlsession_correlation — cat 4 resume/cancel correlation.

Based on run_urlsession_task_correlation's python heredoc in modules/ubs-swift.sh.
Consumes the parsed ast-grep stream records for the
swift.urlsession.task-no-resume rule (stashed on ctx.ast_records by
ubs_core.swift_ast) and correlates each task-creation site with an in-file
resume()/cancel()/return of the assigned variable.

Legacy degradation branches (ast-grep unavailable, stream unusable, no
matches) print info-0 findings or a good note; each maps 1:1 to a record here.
"""
from __future__ import annotations

import re
from bisect import bisect_right


TASK_RID = "swift.urlsession.task-no-resume"
TASK_CALL_RE = re.compile(r"\.\s*(dataTask|uploadTask|downloadTask)\s*\(")

DEGRADED_AST = {
    "rule": "swift.networking.correlation",
    "category": 4,
    "severity": "info",
    "count": 0,
    "title": "Correlation skipped",
    "message": "ast-grep unavailable",
    "description": "ast-grep unavailable",
    "degraded": True,
}

FINDINGS = {
    "ubs.correlation.urlsession.unassigned-no-resume": (
        "warning",
        "URLSession task created but never resumed (result unused)",
        "Call .resume() on the returned task (or return/store it for the caller to resume).",
    ),
    "ubs.correlation.urlsession.assigned-cancel-no-resume": (
        "info",
        "URLSession task cancelled without resume()",
        "If intentional, ignore; otherwise call resume() to start the request (or return it).",
    ),
    "ubs.correlation.urlsession.assigned-no-resume": (
        "warning",
        "URLSession task assigned but no resume() found (in-file)",
        "Call task.resume() after creation, or return/store the task and resume later (ensure lifecycle management).",
    ),
}
def scan(ctx):
    if not ctx.ast_available:
        # legacy: print_finding info 0 "Correlation skipped" "ast-grep unavailable"
        yield dict(DEGRADED_AST)
        return

    task_records = [ent for ent in ctx.ast_records if ent.get("rid") == TASK_RID]
    # Keep the legacy no-task note, but a real AST match must never be rejected
    # because whitespace or comments defeat this inexpensive textual precheck.
    if not task_records and not any(TASK_CALL_RE.search(ctx.text_of(p)) for p in ctx.files):
        yield {
            "rule": "swift.networking.correlation",
            "category": 4,
            "severity": "good",
            "count": 0,
            "title": "No URLSession tasks to correlate",
            "message": "No URLSession tasks to correlate",
            "degraded": True,
        }
        return

    if not getattr(ctx, "ast_stream_ok", False):
        # legacy: empty consolidated stream -> "Could not build ast-grep
        # per-file index" (the AG_STREAM_READY gate)
        yield {
            "rule": "swift.networking.correlation",
            "category": 4,
            "severity": "info",
            "count": 0,
            "title": "Correlation skipped",
            "message": "Could not build ast-grep per-file index",
            "description": "Could not build ast-grep per-file index",
            "degraded": True,
        }
        return

    out = []
    seen = set()

    # group stream records per file, legacy AG_FILE_INDEX semantics
    index = {}
    for ent in task_records:
        index.setdefault(ent.get("file"), []).append(ent)

    for file_key, entries in index.items():
        # ast-grep runs in this process's cwd. Keep its actual source
        # identity for correlation, deduplication, and structured samples.
        abs_path = str(_Path(file_key).resolve())
        try:
            source = _Path(abs_path).read_bytes()
        except OSError:
            continue

        # ast-grep offsets address the original UTF-8 bytes, including CRLF.
        # Decode without universal-newline translation and convert only the
        # actual match/capture boundaries, once per source.
        text = source.decode("utf-8", errors="ignore")
        lines_no_nl = text.split("\n")
        offs = [0]
        for ln in lines_no_nl[:-1]:
            offs.append(offs[-1] + len(ln) + 1)

        sites = []
        boundaries = {0}
        for ent in entries:
            expression = byte_span(ent.get("range"), len(source))
            method = ent.get("method") or {}
            method_span = byte_span(method.get("range"), len(source))
            if expression is None or method_span is None:
                continue
            if not expression[0] <= method_span[0] < method_span[1] <= expression[1]:
                continue
            method_text = source[method_span[0]:method_span[1]]
            if method_text not in (b"dataTask", b"uploadTask", b"downloadTask"):
                continue
            sites.append((ent, expression, method_span))
            boundaries.update((*expression, *method_span))
        positions = {}
        previous_byte = previous_char = 0
        for offset in sorted(boundaries):
            previous_char += len(source[previous_byte:offset].decode("utf-8", errors="ignore"))
            positions[offset] = previous_char
            previous_byte = offset

        for ent, expression, method_span in sites:
            expression_start = positions[expression[0]]
            method_start = positions[method_span[0]]
            row = bisect_right(offs, expression_start) - 1
            expression_col = expression_start - offs[row]
            key = (abs_path, expression[0], method_span[0])
            if key in seen:
                continue
            seen.add(key)

            # The receiver may itself contain calls or span several lines.
            # Parse task arguments at METHOD, but bind the result at the start
            # of the complete receiver expression, before any receiver text.
            call_end = parse_call_end(text, method_start)
            if call_end is None:
                continue

            chain = chained_lifecycle(text, call_end)
            if chain in ("resume", "cancel"):
                continue

            sample = (abs_path, row + 1, int(ent.get("col", 0)) + 1, code_sample(lines_no_nl, row))
            var_expr = extract_assigned_var(lines_no_nl, row, expression_col)
            if not var_expr:
                if has_return_before(lines_no_nl, row, expression_col):
                    continue
                add_finding(
                    out,
                    "ubs.correlation.urlsession.unassigned-no-resume",
                    sample,
                )
                continue

            vregex = var_expr_regex(var_expr)
            var_base = (var_expr.split(".")[-1] if var_expr else "").strip()
            if "." in var_expr:
                assign_re = re.compile(rf"{vregex}\s*=")
            else:
                base = re.escape(var_base)
                assign_re = re.compile(rf"(?:\b(?:let|var)\s+{base}\b|\b{base}\b\s*=)")
            resume_re = re.compile(rf"\b{vregex}\s*(?:[!?]\s*)?\.\s*resume\s*\(")
            cancel_re = re.compile(rf"\b{vregex}\s*(?:[!?]\s*)?\.\s*cancel\s*\(")
            ret_re = re.compile(rf"\breturn\b[^\n]*{vregex}")

            region = text[call_end:]
            mnext = assign_re.search(region)
            region2 = region[: mnext.start()] if mnext else region

            if ret_re.search(region2):
                continue
            if resume_re.search(region2):
                continue
            if cancel_re.search(region2):
                add_finding(out, "ubs.correlation.urlsession.assigned-cancel-no-resume", sample)
                continue

            add_finding(out, "ubs.correlation.urlsession.assigned-no-resume", sample)

    if not out:
        # legacy good note when the ast path ran and found nothing resumable
        yield {
            "rule": "swift.networking.correlation",
            "category": 4,
            "severity": "good",
            "count": 0,
            "title": "All URLSession tasks appear to be resumed/cancelled or returned",
            "message": "All URLSession tasks appear to be resumed/cancelled or returned",
            "degraded": True,
        }
        return
    for fid, sample in out:
        sev, title, desc = FINDINGS[fid]
        path, line, col, code = sample
        yield {
            "rule": fid,
            "category": 4,
            "path": path,
            "line": line,
            "col": col,
            "severity": sev,
            "count": 1,
            "title": f"{fid}: {title}",
            "message": f"{fid}: {title}",
            "description": desc,
            "samples": [{"path": path, "line": line, "col": col, "code": code}],
        }



# --- source-range and lexical helpers --------------------------------------

import re as _re  # noqa: E402
from pathlib import Path as _Path  # noqa: E402


def byte_span(rng, source_size: int):
    """Read ast-grep's inclusive/exclusive UTF-8 range without guessing a site."""
    if not isinstance(rng, dict):
        return None
    offsets = rng.get("byteOffset")
    if not isinstance(offsets, dict):
        return None
    start, end = offsets.get("start"), offsets.get("end")
    if not isinstance(start, int) or not isinstance(end, int):
        return None
    if not 0 <= start < end <= source_size:
        return None
    return start, end


class Lex:
    __slots__ = ("line_comment", "block_comment", "in_string", "raw_hashes", "triple")

    def __init__(self):
        self.line_comment = False
        self.block_comment = 0
        self.in_string = False
        self.raw_hashes = 0
        self.triple = False


def startswith_at(s: str, i: int, lit: str) -> bool:
    return s.startswith(lit, i)


def is_escaped(s: str, i: int) -> bool:
    j = i - 1
    bs = 0
    while j >= 0 and s[j] == "\\":
        bs += 1
        j -= 1
    return (bs % 2) == 1


def enter_string(s: str, i: int, lex: Lex) -> int:
    if s[i] == '"':
        if startswith_at(s, i, '"""'):
            lex.in_string = True
            lex.raw_hashes = 0
            lex.triple = True
            return i + 3
        lex.in_string = True
        lex.raw_hashes = 0
        lex.triple = False
        return i + 1
    if s[i] == "#":
        j = i
        while j < len(s) and s[j] == "#":
            j += 1
        if j < len(s) and s[j] == '"':
            if startswith_at(s, j, '"""'):
                lex.in_string = True
                lex.raw_hashes = j - i
                lex.triple = True
                return j + 3
            lex.in_string = True
            lex.raw_hashes = j - i
            lex.triple = False
            return j + 1
    return i + 1


def scan_balanced(s: str, start: int, open_ch: str, close_ch: str):
    i = start
    depth = 0
    lex = Lex()
    while i < len(s):
        ch = s[i]
        nxt = s[i + 1] if i + 1 < len(s) else ""
        if lex.line_comment:
            if ch == "\n":
                lex.line_comment = False
            i += 1
            continue
        if lex.block_comment > 0:
            if ch == "/" and nxt == "*":
                lex.block_comment += 1
                i += 2
                continue
            if ch == "*" and nxt == "/":
                lex.block_comment -= 1
                i += 2
                continue
            i += 1
            continue
        if lex.in_string:
            if lex.triple:
                end_delim = '"""' + ("#" * lex.raw_hashes)
                if startswith_at(s, i, end_delim):
                    lex.in_string = False
                    i += len(end_delim)
                    continue
                i += 1
                continue
            if lex.raw_hashes > 0:
                end_delim = '"' + ("#" * lex.raw_hashes)
                if startswith_at(s, i, end_delim):
                    lex.in_string = False
                    i += len(end_delim)
                    continue
                i += 1
                continue
            if ch == '"' and not is_escaped(s, i):
                lex.in_string = False
                i += 1
                continue
            i += 1
            continue
        if ch == "/" and nxt == "/":
            lex.line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            lex.block_comment = 1
            i += 2
            continue
        if ch == '"' or ch == "#":
            i = enter_string(s, i, lex)
            continue
        if ch == open_ch:
            depth += 1
            i += 1
            continue
        if ch == close_ch:
            depth -= 1
            i += 1
            if depth == 0:
                return i
            continue
        i += 1
    return None


def skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i].isspace():
        i += 1
    return i


def parse_call_end(s: str, call_start: int):
    open_paren = s.find("(", call_start)
    if open_paren < 0:
        return None
    end_args = scan_balanced(s, open_paren, "(", ")")
    if end_args is None:
        return None
    i = end_args
    while True:
        i = skip_ws(s, i)
        if i >= len(s):
            break
        if s[i] == "{":
            end_cl = scan_balanced(s, i, "{", "}")
            if end_cl is None:
                return i
            i = end_cl
            continue
        m = _re.match(r"[A-Za-z_]\w*\s*:\s*", s[i:])
        if m:
            j = skip_ws(s, i + m.end())
            if j < len(s) and s[j] == "{":
                end_cl = scan_balanced(s, j, "{", "}")
                if end_cl is None:
                    return j
                i = end_cl
                continue
        break
    return i


def chained_lifecycle(s: str, call_end: int):
    i = skip_ws(s, call_end)
    if i >= len(s):
        return None
    if s[i] in "?!":
        j = skip_ws(s, i + 1)
        if j < len(s) and s[j] == ".":
            i = j
        else:
            return None
    if s[i] != ".":
        return None
    j = skip_ws(s, i + 1)
    for name in ("resume", "cancel"):
        if s.startswith(name, j):
            k = skip_ws(s, j + len(name))
            if k < len(s) and s[k] == "(":
                return name
    return None


def collapse_ws(s: str) -> str:
    return _re.sub(r"\s+", "", s or "")


def var_expr_regex(expr: str) -> str:
    parts = [p for p in (expr or "").split(".") if p]
    return r"\s*\.\s*".join(_re.escape(p) for p in parts)


def parse_lhs_assignment(lhs: str):
    lhs = (lhs or "").rstrip()
    m = _re.search(
        r"\b(?:let|var)\s+([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*(?::[^=]+)?\s*=\s*$",
        lhs,
    )
    if m:
        name = collapse_ws(m.group(1))
        return name if name != "_" else None
    m = _re.search(
        r"([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*(?::[^=]+)?\s*=\s*$",
        lhs,
    )
    if m:
        name = collapse_ws(m.group(1))
        return name if name != "_" else None
    return None


def extract_assigned_var(lines_no_nl, row: int, call_col: int):
    if row < 0 or row >= len(lines_no_nl):
        return None
    line = lines_no_nl[row]
    lhs = line[: max(0, min(call_col, len(line)))]
    v = parse_lhs_assignment(lhs)
    if v:
        return v
    if row > 0 and not lhs.strip():
        prev = lines_no_nl[row - 1].split("//", 1)[0]
        if prev.rstrip().endswith("="):
            v = parse_lhs_assignment(prev.rstrip())
            if v:
                return v
    return None


def has_return_before(lines_no_nl, row: int, call_col: int) -> bool:
    if row < 0 or row >= len(lines_no_nl):
        return False
    prefix = lines_no_nl[row][: max(0, min(call_col, len(lines_no_nl[row])))]
    if _re.search(r"\breturn\s*$", prefix):
        return True
    if not prefix.strip() and row > 0 and _re.search(r"\breturn\s*$", lines_no_nl[row - 1]):
        return True
    return False


def code_sample(lines_no_nl, row: int) -> str:
    if row < 0 or row >= len(lines_no_nl):
        return ""
    return (lines_no_nl[row] or "").strip().replace("\t", " ")


def add_finding(out: list, fid: str, sample) -> None:
    # Keep every actual source occurrence. Rendering may limit previews only
    # after the complete selected-file records have been replayed from cache.
    out.append((fid, sample))
