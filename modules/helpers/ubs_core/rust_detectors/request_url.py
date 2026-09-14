"""ubs_core.rust_detectors.request_url — request-derived outbound-URL taint (bead 0xjg.7).

Port of rust_request_url_matches (modules/ubs-rust.sh 3442-3695).

Bindings are tracked through lexical blocks and reset at function boundaries.
Only URL operands contribute value references; callable names and literal text
cannot inherit an unrelated binding's taint. Source suppression keeps bare and
rule-scoped markers distinct so a diagnostic marker cannot erase propagation.

The legacy heredoc consumed UBS_RUST_FILE_LIST (GH #70) or rglob'd the tree;
`find(files)` instead iterates the orchestrator's already-filtered file list in
order. The legacy code never called .resolve() on list entries, so neither does
this port; the local skip_dirs set is kept for documentation only.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from pathlib import Path
from typing import Iterator

from ubs_core.io import find_block_end
from ubs_core.lexer import strip_comments_and_strings
from ubs_core.suppression import SourceSuppressions, has_suppression_marker

RULE_ID = "rust.security.request-url"
CATEGORY = 8
TITLE = "Request-derived URL reaches outbound HTTP client"
SEVERITY = "critical"
DESCRIPTION = (
    "Validate outbound URLs with explicit scheme and host allow-lists before "
    "sending client requests"
)

skip_dirs = {".git", "target", ".cargo", "node_modules"}  # documentation-only (see module docstring)
path_limit = 4

source_re = re.compile(
    r'\b(?:std::)?env::(?:var|var_os)\s*\(\s*"[^"]*(?:URL|URI|HOST|CALLBACK|WEBHOOK|REDIRECT|TARGET|ENDPOINT|REMOTE)[^"]*"\s*\)'
    r'|\b(?:std::)?env::args(?:_os)?\s*\('
    r'|\b(?:req|request|http_request)\s*\.\s*(?:query_string|uri|headers|header|host)\s*\('
    r'|\b(?:headers|header_map)\s*\.\s*get\s*\(\s*"[^"]*(?:url|uri|host|callback|webhook|redirect|target|endpoint|origin|referer|referrer|location)[^"]*"\s*\)'
    r'|\b(?:params|query|form|body|json|payload|headers)\s*\.\s*get\s*\(\s*"[^"]*(?:url|uri|host|callback|webhook|redirect|target|endpoint|origin|remote)[^"]*"\s*\)'
    r'|\b(?:params|query|form|body|json|payload)\s*\.\s*(?:url|uri|host|callback_url|webhook_url|redirect_url|target_url|endpoint|remote_url)\b',
    re.IGNORECASE,
)
sink_re = re.compile(
    r'\breqwest(?:::blocking)?::(?:get|Client::new\(\)\.(?:get|post|put|patch|delete|head|request))\s*\('
    r'|\bureq::(?:get|post|put|delete|patch|head|request)\s*\('
    r'|\bsurf::(?:get|post|put|delete|patch|head|request)\s*\('
    r'|\bisahc::(?:get|post|put|delete|patch|head|request)\s*\('
    r'|\b(?:hyper|http)::Request::builder\s*\(\s*\)\s*\.\s*uri\s*\('
    r'|\b(?:client|http_client|reqwest_client|rest_client|web_client|agent|request_builder|builder|api_client|webhook_client)\s*\.\s*(?:get|post|put|patch|delete|head|request|uri)\s*\(',
    re.IGNORECASE,
)
assign_re = re.compile(
    r'(?<![A-Za-z0-9_:.])(?:(?P<declaration>let|const|static)\s+(?:(?:ref|mut)\s+)*)?'
    r'(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::(?!:)[^=;{}]+)?=(?![=>])\s*'
)
safe_expr_re = re.compile(
    r'\b(?:safe(?:URL|Url|Uri|URI|OutboundURL|OutboundUrl|OutboundURI|WebhookURL|CallbackURL|HttpURL)|'
    r'safe_(?:url|uri|outbound_url|webhook_url|callback_url|http_url)|'
    r'validated?(?:URL|Url|Uri|URI|Host|OutboundURL|WebhookURL|CallbackURL)|'
    r'validate_(?:url|uri|host|outbound_url|webhook_url|callback_url)|'
    r'allowed?(?:URL|Url|Uri|URI|Host|OutboundURL)|'
    r'allowlisted?(?:URL|Url|Uri|URI|Host|OutboundURL)|'
    r'is_allowed_host|is_safe_url|allowed_hosts|host_allowlist|trusted_hosts)\b',
    re.IGNORECASE,
)
parse_re = re.compile(r'\b(?:url::)?Url::parse\s*\(|\.parse\s*::\s*<\s*(?:hyper::)?Uri\s*>\s*\(')
host_check_re = re.compile(
    r'\b(?:host_str|domain|scheme|allowed_hosts|host_allowlist|trusted_hosts|is_allowed_host|is_safe_url)\b'
)
reject_re = re.compile(r'\b(?:return\s+Err|Err\s*\(|bail!\s*\(|ensure!\s*\(|anyhow!\s*\(|panic!\s*\()\b')


def rust_files(files):
    """Legacy rust_files(): consume the orchestrator's authoritative filtered
    file list (--exclude / --strict-gitignore / --exclude-tests) instead of
    re-walking the tree with a local skip list. The legacy listing path kept
    .rs entries only and never resolved them."""
    for entry in files:
        if entry.suffix == ".rs":
            yield entry


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


def logical_statement(lines, line_no):
    idx = line_no - 1
    statement = strip_line_comments(lines[idx])
    paren = statement.count("(") - statement.count(")")
    has_end = ";" in statement or "{" in statement or "}" in statement
    lookahead = idx + 1
    while (paren > 0 or not has_end) and lookahead < len(lines) and lookahead < idx + 10:
        nxt = strip_line_comments(lines[lookahead]).strip()
        statement += " " + nxt
        paren += nxt.count("(") - nxt.count(")")
        has_end = has_end or ";" in nxt or "{" in nxt or "}" in nxt
        lookahead += 1
    return statement


def has_ignore(lines, line_no, rule=None):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and has_suppression_marker(lines[idx], rule)
    ) or (
        0 <= idx - 1 < len(lines) and has_suppression_marker(lines[idx - 1], rule)
    )


def is_safe_expr(expr: str) -> bool:
    return bool(safe_expr_re.search(expr))


def refs_in_expr(expr: str, tainted):
    # Assignment names are ASCII identifiers. Keep Unicode word boundaries
    # and taint insertion order, without compiling a regex for every name.
    names = set(re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', expr))
    return [name for name in tainted if name in names]


def taint_from_expr(expr: str, tainted):
    if is_safe_expr(expr):
        return None
    direct = source_re.search(expr)
    if direct:
        return {"path": [direct.group(0).strip()]}
    refs = refs_in_expr(expr, tainted)
    if not refs:
        return None
    ref = refs[0]
    path = list(tainted.get(ref, {}).get("path", [ref]))
    if len(path) >= path_limit:
        path = path[-(path_limit - 1):]
    path.append(ref)
    return {"path": path}


def has_allowlist_context(lines, line_no, refs, scope_start=1):
    if not refs:
        return False
    start = max(scope_start - 1, line_no - 24)
    context = "\n".join(strip_line_comments(line) for line in lines[start:line_no + 1])
    if not any(re.search(rf'\b{re.escape(ref)}\b', context) for ref in refs):
        return False
    for line in context.splitlines():
        if safe_expr_re.search(line) and any(re.search(rf'\b{re.escape(ref)}\b', line) for ref in refs):
            return True
    return bool(parse_re.search(context) and host_check_re.search(context) and reject_re.search(context))


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip().replace("\t", " ")
    return ""


def value_references(expr):
    """Retain value names, not literal text, field labels or callable paths."""
    masked = strip_comments_and_strings(expr, lang="rust")
    chars = list(masked)
    for match in re.finditer(r'\b[A-Za-z_][A-Za-z0-9_]*\b', masked):
        before = masked[:match.start()].rstrip()
        after = masked[match.end():].lstrip()
        if (before.endswith((".", "::")) or after.startswith(("::", "(", "!"))
                or (after.startswith(":") and not after.startswith("::"))):
            chars[match.start():match.end()] = " " * len(match.group())
    # Rust format! can capture a variable without a separate argument. Other
    # string contents (including documented Rust code) are not value references.
    captures = []
    if re.search(r'\bformat\s*!', masked):
        captures = re.findall(r'(?<!\{)\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^{}]*)?\}(?!\})', expr)
    return "".join(chars) + " " + " ".join(captures)


def value_taint(expr, bindings):
    masked = strip_comments_and_strings(expr, lang="rust")
    if is_safe_expr(masked):
        return None
    for source in source_re.finditer(expr):
        if masked[source.start():source.start() + 1].strip():
            return {"path": [source.group(0).strip()]}
    return taint_from_expr(value_references(expr), bindings)


def expression_end(masked, start):
    """Find the end of an initializer without crossing its containing block."""
    stack = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    for pos in range(start, len(masked)):
        char = masked[pos]
        if char in pairs:
            stack.append(pairs[char])
        elif stack and char == stack[-1]:
            stack.pop()
        elif not stack and char in ";}":
            return pos
    return len(masked)


def call_arguments(masked, opening):
    closing = find_block_end(masked, opening, "(", ")")
    if closing <= opening or masked[closing] != ")":
        return []
    args = []
    start = opening + 1
    stack = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    for pos in range(start, closing):
        char = masked[pos]
        if char in pairs:
            stack.append(pairs[char])
        elif stack and char == stack[-1]:
            stack.pop()
        elif char == "," and not stack:
            args.append((start, pos))
            start = pos + 1
    args.append((start, closing))
    return args


def function_bodies(masked):
    bodies = {}
    for declaration in re.finditer(r'\bfn\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^{};]*>)?\s*\(', masked):
        closing = find_block_end(masked, declaration.end() - 1, "(", ")")
        opening = masked.find("{", closing + 1)
        terminator = masked.find(";", closing + 1)
        if opening >= 0 and (terminator < 0 or opening < terminator):
            bodies[opening] = declaration.start()
    return bodies


def analyze(path: Path, issues):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if not (source_re.search(text) and sink_re.search(text)):
        return
    lines = text.splitlines()
    line_starts = [0] + [match.end() for match in re.finditer("\n", text)]
    source = strip_comments_and_strings(text, lang="rust", strip_strings=False)
    masked = strip_comments_and_strings(text, lang="rust")
    suppressions = SourceSuppressions("rust")
    suppressions.index(path, text)
    bodies = function_bodies(masked)
    # A function item cannot capture enclosing local variables. Ordinary
    # blocks and closures can, but their declarations must shadow outer names.
    scopes = [{"bindings": {}, "function": True, "start": 1}]
    events = [(match.start(), "brace", match.group())
              for match in re.finditer(r'[{}]', masked)]
    events.extend((match.start(), "assignment", match) for match in assign_re.finditer(masked))
    events.extend((match.start(), "sink", match) for match in sink_re.finditer(masked))
    seen = set()
    for offset, kind, event in sorted(events, key=lambda item: item[0]):
        line_no = bisect_right(line_starts, offset)
        if kind == "brace":
            if event == "}":
                if len(scopes) > 1:
                    scopes.pop()
            else:
                boundary = offset in bodies
                frame = {"bindings": {}, "function": boundary,
                         "start": bisect_right(line_starts, bodies.get(offset, offset))}
                if not boundary:
                    previous = max(masked.rfind(";", 0, offset), masked.rfind("{", 0, offset),
                                   masked.rfind("}", 0, offset))
                    header = masked[previous + 1:offset]
                    closure = re.search(r'\|([^|]*)\|\s*(?:->[^{}]+)?$', header)
                    if closure:
                        for parameter in closure.group(1).split(","):
                            name = re.match(r'\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)', parameter)
                            if name:
                                frame["bindings"][name.group(1)] = None
                    loop = re.search(r'\bfor\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+in\b', header)
                    if loop:
                        frame["bindings"][loop.group(1)] = None
                scopes.append(frame)
            continue

        visible = {}
        function_start = 1
        for scope in reversed(scopes):
            for name, binding in scope["bindings"].items():
                visible.setdefault(name, binding)
            if scope["function"]:
                function_start = scope["start"]
                break
        tainted = {name: binding for name, binding in visible.items() if binding is not None}
        if kind == "assignment":
            name = event.group("lhs")
            rhs = source[event.end():expression_end(masked, event.end())]
            taint = None if suppressions.is_suppressed(path, line_no, None) else value_taint(rhs, tainted)
            if taint is not None:
                taint["line"] = line_no
            target = scopes[-1]
            if not event.group("declaration"):
                for scope in reversed(scopes):
                    if name in scope["bindings"]:
                        target = scope
                        break
                    if scope["function"]:
                        break
                # A conditional block/closure may not run. Do not erase a
                # tainted outer binding merely because one branch assigns clean.
                if target is not scopes[-1] and taint is None:
                    taint = target["bindings"].get(name)
            target["bindings"][name] = taint
            continue

        args = call_arguments(masked, event.end() - 1)
        method = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\($', event.group())
        index = 1 if method and method.group(1).lower() == "request" else 0
        if len(args) <= index:
            continue
        start, end = args[index]
        argument = source[start:end]
        taint = value_taint(argument, tainted)
        if taint is None:
            continue
        refs = refs_in_expr(value_references(argument), tainted)
        scope_start = max([function_start] + [tainted[ref].get("line", 1) for ref in refs])
        if has_allowlist_context(lines, line_no, refs, scope_start):
            continue
        if suppressions.is_suppressed(path, line_no, RULE_ID):
            continue
        key = (path, line_no)
        if key in seen:
            continue
        seen.add(key)
        seq = list(taint["path"])
        if len(seq) >= path_limit:
            seq = seq[-(path_limit - 1):]
        seq.append("outbound HTTP")
        path_desc = " -> ".join(seq)
        issues.append((path, line_no, f"{source_line(lines, line_no)}  [{path_desc}]"))


def find(files) -> Iterator[tuple[Path, int, int, str]]:
    """Yield (path, line, col, code) per legacy deduped finding, in legacy order."""
    issues = []
    for rust_file in rust_files(files):
        analyze(rust_file, issues)
    for path, line_no, code in issues:
        yield path, line_no, 1, code


if __name__ == "__main__":
    import sys
    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
