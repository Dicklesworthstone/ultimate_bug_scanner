"""swift_detectors.urlsession_correlation — cat 4 resume/cancel correlation.

Verbatim port of run_urlsession_task_correlation's python heredoc in
modules/ubs-swift.sh. Consumes the parsed ast-grep stream records for the
swift.urlsession.task-no-resume rule (stashed on ctx.ast_records by
ubs_core.swift_ast) and correlates each task-creation site with an in-file
resume()/cancel()/return of the assigned variable.

Legacy degradation branches (ast-grep unavailable, stream unusable, no
matches) print info-0 findings or a good note; each maps 1:1 to a record here.
"""
from __future__ import annotations

import re


TASK_RID = "swift.urlsession.task-no-resume"
TASK_CALL_RE = re.compile(r"\.(dataTask|uploadTask|downloadTask)\s*\(")

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
    import os

    if not ctx.ast_available:
        # legacy: print_finding info 0 "Correlation skipped" "ast-grep unavailable"
        yield dict(DEGRADED_AST)
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

    project_dir = str(ctx.project_dir)

    # legacy rg precheck (no marker filter): any dataTask-ish match proceeds
    if not any(TASK_CALL_RE.search(ctx.text_of(p)) for p in ctx.files):
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

    def norm_path(p: str) -> str:
        if os.path.isabs(p):
            return p
        return os.path.normpath(os.path.join(project_dir, p))

    def rel(p: str) -> str:
        try:
            rp = os.path.relpath(p, project_dir)
            return rp if not rp.startswith("..") else p
        except Exception:
            return p

    out = {}
    seen = set()

    # group stream records per file, legacy AG_FILE_INDEX semantics
    index = {}
    for ent in ctx.ast_records:
        if (ent.get("rid") or "") != TASK_RID:
            continue
        index.setdefault(ent.get("file"), []).append(ent)

    for file_key, entries in index.items():
        abs_path = norm_path(file_key)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except Exception:
            continue

        lines = text.splitlines(True)
        lines_no_nl = [ln.rstrip("\n") for ln in lines]
        offs = [0]
        for ln in lines:
            offs.append(offs[-1] + len(ln))

        for ent in entries or []:
            try:
                row = int(ent.get("row", 0))
                col = int(ent.get("col", 0))
            except Exception:
                row, col = 0, 0
            if row < 0 or row >= len(lines):
                continue

            line = lines[row]
            call_col = max(0, min(col, len(line)))
            seg = line[call_col:]
            m = TASK_CALL_RE.search(seg)
            if m:
                call_col += m.start()
            else:
                m = TASK_CALL_RE.search(line)
                if not m:
                    continue
                call_col = m.start()

            key = (abs_path, row, call_col)
            if key in seen:
                continue
            seen.add(key)

            call_start = offs[row] + call_col
            call_end = parse_call_end(text, call_start)
            if call_end is None:
                continue

            chain = chained_lifecycle(text, call_end)
            if chain in ("resume", "cancel"):
                continue

            sample = (rel(abs_path), row + 1, code_sample(lines_no_nl, row))
            var_expr = extract_assigned_var(lines_no_nl, row, call_col)
            if not var_expr:
                if has_return_before(lines_no_nl, row, call_col):
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
    for fid, data in out.items():
        sev, title, desc = FINDINGS[fid]
        yield {
            "rule": fid,
            "category": 4,
            "path": data["samples"][0][0] if data["samples"] else "",
            "line": data["samples"][0][1] if data["samples"] else 0,
            "severity": sev,
            "count": data["count"],
            "title": f"{fid}: {title}",
            "message": f"{fid}: {title}",
            "description": desc,
            "samples": [
                {"path": f, "line": ln, "code": code} for f, ln, code in data["samples"]
            ],
        }



# --- the heredoc's helper functions (verbatim) -------------------------------

import re as _re  # noqa: E402
from pathlib import Path as _Path  # noqa: E402


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
        return collapse_ws(m.group(1))
    m = _re.search(
        r"([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*(?::[^=]+)?\s*=\s*$",
        lhs,
    )
    if m:
        return collapse_ws(m.group(1))
    return None


def extract_assigned_var(lines_no_nl, row: int, call_col: int):
    if row < 0 or row >= len(lines_no_nl):
        return None
    line = lines_no_nl[row]
    lhs = line[: max(0, min(call_col, len(line)))]
    v = parse_lhs_assignment(lhs)
    if v:
        return v
    if row > 0:
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
    if _re.search(r"\breturn\b", prefix):
        return True
    if row > 0 and _re.search(r"\breturn\s*$", lines_no_nl[row - 1]):
        return True
    return False


def code_sample(lines_no_nl, row: int) -> str:
    if row < 0 or row >= len(lines_no_nl):
        return ""
    return (lines_no_nl[row] or "").strip().replace("\t", " ")


def add_finding(out: dict, fid: str, sample) -> None:
    sev, title, desc = FINDINGS[fid]
    b = out.setdefault(fid, {"severity": sev, "title": title, "desc": desc,
                             "count": 0, "samples": []})
    b["count"] += 1
    if sample and len(b["samples"]) < 3:
        f, ln, code = sample
        code = (code or "").replace("\t", " ").strip()
        b["samples"].append((f, ln, code))
