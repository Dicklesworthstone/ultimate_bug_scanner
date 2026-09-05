"""ubs_core.analyzers.spec_hooks — React hooks dependency analysis
(bead A4-js final wave).

Verbatim port of ubs-js.sh ``run_hooks_dependency_checks`` (799-1218): the 8
ast-grep rules (useEffect/useLayoutEffect/useCallback/useMemo, each with and
without a dependency array) plus the aggregator heredoc that classifies every
match into:

- ``js.hooks.no-deps``          warning   hook called without a dependency array
- ``js.hooks.missing-critical`` critical  missing dependency that is a prop
- ``js.hooks.missing-warning``  warning   missing state/ref/other dependency
- ``js.hooks.unstable``         critical  object/array/inline-fn dep entry
- ``js.hooks.unused``           info      dependency entry never read in the callback

The ast-grep ``$CALLBACK``/``$DEPS`` meta-variables are reproduced with an
offset-preserving scanner (comments, quoted strings, template-literal text
and regex literals are blanked out; ``${...}`` interpolation code stays
visible), so the aggregator's text-level regexes see byte-identical
callback/DEPS slices.  Every aggregator helper (KEYWORDS, BUILTINS, the
props/state/refs/module-fn symbol patterns, parse_deps, classify, skip_name,
is_literal, is_unstable, calc_line) is ported unchanged — including
``calc_line``'s verbatim ``\\b``-doubling, which makes the pattern match only
a literal ``\\b<name>\\b`` sequence, so legacy effectively reports every
missing dependency on the callback's first line.

The legacy hooks pipeline applies no ``ubs:ignore`` suppression anywhere (the
aggregator consumes the raw ast-grep JSON stream), so none is added here.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from ubs_core.registry import Analyzer, RunContext, register

EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

RULE_NO_DEPS = "js.hooks.no-deps"
RULE_MISSING_CRITICAL = "js.hooks.missing-critical"
RULE_MISSING_WARNING = "js.hooks.missing-warning"
RULE_UNSTABLE = "js.hooks.unstable"
RULE_UNUSED = "js.hooks.unused"
CATEGORY_ID = "js.hooks"

# HOOKS_SEVERITY (ubs-js.sh 175-181).
SEVERITIES = {
    RULE_NO_DEPS: "warning",
    RULE_MISSING_CRITICAL: "critical",
    RULE_MISSING_WARNING: "warning",
    RULE_UNSTABLE: "critical",
    RULE_UNUSED: "info",
}

# Ast-grep matches bare call expressions only: `React.useEffect(...)`,
# `obj.useMemo(...)`, `new useCallback(...)`, `function useEffect(...)` and
# class/object method shorthand are different AST nodes and never matched.
HOOK_CALL_RE = re.compile(r"(?<![.\w$])(useEffect|useLayoutEffect|useCallback|useMemo)\s*\(")

# Legacy rule ids of the no-deps family — the heredoc builds the finding text
# via `rule.split('.')[-2]`, which is 'hooks' for every one of them.
_NO_DEPS_AST_RULE = "hooks.use-effect-no-deps"
NO_DEPS_MESSAGE = f"{_NO_DEPS_AST_RULE.split('.')[-2]} is missing a dependency array"


# ─────────────────────────────────────────────────────────────────────────────
# $CALLBACK / $DEPS extraction (offset-preserving lexical mask)
# ─────────────────────────────────────────────────────────────────────────────
def mask_source(text: str) -> str:
    """Same-length copy of *text* with non-code characters blanked.

    Comments, quoted-string bodies, template-literal text and regex literals
    become spaces (newlines preserved, so every offset stays valid); the
    ``${...}`` interpolation code inside template literals remains visible.
    """
    out = list(text)
    n = len(text)

    def blank(idx: int) -> None:
        if out[idx] != "\n":
            out[idx] = " "

    def mask_line_comment(i: int) -> int:
        while i < n and text[i] not in "\r\n":
            blank(i)
            i += 1
        return i

    def mask_block_comment(i: int) -> int:
        i += 2
        while i < n:
            if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                blank(i)
                blank(i + 1)
                return i + 2
            blank(i)
            i += 1
        return i

    def mask_quoted(i: int, quote: str) -> int:
        i += 1
        while i < n:
            ch = text[i]
            if ch == "\\":
                blank(i)
                if i + 1 < n:
                    blank(i + 1)
                i += 2
                continue
            if ch == quote:
                return i + 1
            blank(i)
            i += 1
        return i

    def mask_template(i: int) -> int:
        i += 1
        while i < n:
            ch = text[i]
            if ch == "\\":
                blank(i)
                if i + 1 < n:
                    blank(i + 1)
                i += 2
                continue
            if ch == "`":
                return i + 1
            if ch == "$" and i + 1 < n and text[i + 1] == "{":
                i = mask_interpolation(i + 2)
                continue
            blank(i)
            i += 1
        return i

    def mask_interpolation(i: int) -> int:
        depth = 1
        while i < n and depth:
            ch = text[i]
            if ch == "{":
                depth += 1
                i += 1
            elif ch == "}":
                depth -= 1
                if not depth:
                    return i + 1
                i += 1
            elif ch == "/" and i + 1 < n and text[i + 1] == "/":
                i = mask_line_comment(i)
            elif ch == "/" and i + 1 < n and text[i + 1] == "*":
                i = mask_block_comment(i)
            elif ch in "\"'":
                i = mask_quoted(i, ch)
            elif ch == "`":
                i = mask_template(i)
            else:
                i += 1
        return i

    def prev_significant(i: int) -> str:
        j = i - 1
        while j >= 0 and out[j] in " \t\r\n":
            j -= 1
        return out[j] if j >= 0 else ""

    i = 0
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i = mask_line_comment(i)
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            i = mask_block_comment(i)
        elif ch in "\"'":
            i = mask_quoted(i, ch)
        elif ch == "`":
            i = mask_template(i)
        elif ch == "/":
            prev = prev_significant(i)
            if prev and (prev.isalnum() or prev in ")]}\"'`_$"):
                i += 1  # division, not a regex literal
                continue
            i += 1
            in_class = False
            while i < n:
                c2 = text[i]
                if c2 == "\\":
                    blank(i)
                    if i + 1 < n:
                        blank(i + 1)
                    i += 2
                    continue
                if c2 == "\n":
                    break  # never terminated — was not a regex after all
                if c2 == "[":
                    in_class = True
                elif c2 == "]":
                    in_class = False
                elif c2 == "/" and not in_class:
                    i += 1
                    while i < n and (text[i].isalnum()):
                        i += 1  # flags
                    break
                blank(i)
                i += 1
        else:
            i += 1
    return "".join(out)


def _match_paren(masked: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(masked)):
        ch = masked[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _split_args(masked: str, open_idx: int, close_idx: int) -> list[tuple[int, int]]:
    args: list[tuple[int, int]] = []
    depth = 0
    start = open_idx + 1
    for i in range(open_idx + 1, close_idx):
        ch = masked[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append((start, i))
            start = i + 1
    args.append((start, close_idx))
    # A trailing comma is not an argument: `f(a, b,)` is a two-argument call.
    if len(args) >= 2 and not masked[args[-1][0]:args[-1][1]].strip():
        args.pop()
    return args


def _code_span(masked: str, span: tuple[int, int]) -> tuple[int, int] | None:
    """Exact source span of one argument (first..last non-trivia char).

    Returns None for a blank argument (`useEffect()`, a comment-only slot).
    """
    start, end = span
    while start < end and masked[start] in " \t\r\n":
        start += 1
    while end > start and masked[end - 1] in " \t\r\n":
        end -= 1
    return None if start >= end else (start, end)


def _prev_word(masked: str, idx: int) -> str:
    j = idx - 1
    while j >= 0 and masked[j] in " \t\r\n":
        j -= 1
    end = j + 1
    while j >= 0 and (masked[j].isalnum() or masked[j] in "_$"):
        j -= 1
    return masked[j + 1:end]


def _next_significant(masked: str, idx: int) -> str:
    j = idx + 1
    while j < len(masked) and masked[j] in " \t\r\n":
        j += 1
    return masked[j] if j < len(masked) else ""


def find_hook_calls(text: str) -> list[tuple[int, int, str, int, str | None]]:
    """One entry per syntactic hook call, in source order:
    (hook_line0, hook_col1, callback_text, callback_start0, deps_text|None).
    ``deps_text is None`` marks a single-argument (no-deps) call.
    """
    masked = mask_source(text)
    calls: list[tuple[int, int, str, int, str | None]] = []
    for match in HOOK_CALL_RE.finditer(masked):
        ident_start = match.start(1)
        open_idx = match.end() - 1
        if _prev_word(masked, ident_start) in ("new", "function"):
            continue  # constructor / declaration, not a call expression
        close_idx = _match_paren(masked, open_idx)
        if close_idx < 0:
            continue
        if _next_significant(masked, close_idx) == "{":
            continue  # class/object method shorthand body, not a call
        args = _split_args(masked, open_idx, close_idx)
        if len(args) > 2:
            continue  # no legacy rule matches other arities
        spans = [_code_span(masked, arg) for arg in args]
        if any(span is None for span in spans):
            continue  # `useEffect()` has no $CALLBACK node to match
        hook_line0 = text.count("\n", 0, ident_start)
        line_start = text.rfind("\n", 0, ident_start) + 1
        hook_col1 = ident_start - line_start + 1
        callback_span, deps_span = spans[0], (spans[1] if len(spans) == 2 else None)
        cb_start, cb_end = callback_span
        callback_text = text[cb_start:cb_end]
        if deps_span is None:
            calls.append((hook_line0, hook_col1, callback_text, text.count("\n", 0, cb_start), None))
        else:
            ds, de = deps_span
            calls.append((hook_line0, hook_col1, callback_text, text.count("\n", 0, cb_start), text[ds:de]))
    return calls


# ─────────────────────────────────────────────────────────────────────────────
# Aggregator heredoc (ubs-js.sh 906-1211) — verbatim below this point.
# ─────────────────────────────────────────────────────────────────────────────
KEYWORDS = {
    'const', 'let', 'var', 'return', 'if', 'else', 'switch', 'case', 'break', 'continue',
    'for', 'while', 'do', 'class', 'function', 'async', 'await', 'default', 'new', 'typeof',
    'try', 'catch', 'finally', 'throw', 'import', 'from', 'export', 'extends', 'super',
    'true', 'false', 'null', 'undefined', 'NaN', 'Infinity',
    # GH #93: operator/TS keywords — hooks rules now run on .ts/.tsx, where
    # `void fn()`, `x as T`, and type annotations put these in callback text.
    'void', 'delete', 'in', 'of', 'yield', 'instanceof', 'this', 'static',
    'get', 'set', 'as', 'satisfies', 'keyof', 'readonly', 'infer', 'is',
    'asserts', 'type', 'interface', 'enum', 'declare', 'namespace', 'abstract',
    'implements', 'public', 'private', 'protected', 'override',
    'string', 'number', 'boolean', 'unknown', 'any', 'never', 'object',
    'symbol', 'bigint',
}

BUILTINS = {
    'console', 'Math', 'JSON', 'Number', 'String', 'Boolean', 'Promise', 'Date', 'window',
    'document', 'fetch', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'log',
    'apply'
}
STATE_PATTERN = re.compile(r"const\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]\s*=\s*useState", re.MULTILINE)
REF_PATTERN = re.compile(r"const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*useRef\(", re.MULTILINE)
MODULE_FN_PATTERN = re.compile(r"^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
MODULE_CONST_FN_PATTERN = re.compile(r"^(?:export\s+)?const\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=\n]+)?=\s*(?:async\s*)?(?:function\b|\()", re.MULTILINE)
PROPS_FUNC_PATTERN = re.compile(r"function\s+[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\{([^}]*)\}\s*\)")
ARROW_FUNC_PATTERN = re.compile(r"=\s*\(\s*\{([^}]*)\}\s*\)\s*=>")
DESTRUCT_PROPS_PATTERN = re.compile(r"const\s*\{([^}]*)\}\s*=\s*props")

STRING_RE = re.compile(r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')", re.S)
COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n\r]*", re.S)


def parse_props(blob):
    names = []
    for raw in blob.split(','):
        token = raw.strip()
        if not token:
            continue
        name = token.split('=')[0].strip()
        if not name:
            continue
        name = name.replace('*', '').strip()
        name = name.strip('()')
        if name:
            names.append(name)
    return names


def get_file_symbols(text):
    """Symbol table for one file's text.  The heredoc read the file strictly
    and fell back to empty symbols on any decode error — the caller keeps that
    semantics; the heredoc's file_cache existed only because the ast-grep
    stream repeats the same file once per rule."""
    state_vars, setters = set(), set()
    for match in STATE_PATTERN.finditer(text):
        state_vars.add(match.group(1))
        setters.add(match.group(2))
    ref_vars = {m.group(1) for m in REF_PATTERN.finditer(text)}
    props = set()
    for pattern in (PROPS_FUNC_PATTERN, ARROW_FUNC_PATTERN, DESTRUCT_PROPS_PATTERN):
        for match in pattern.finditer(text):
            props.update(parse_props(match.group(1)))
    # GH #93: module-level (column-0) function declarations are stable across
    # renders and must not be suggested as hook dependencies.
    module_fns = {m.group(1) for m in MODULE_FN_PATTERN.finditer(text)}
    module_fns.update(m.group(1) for m in MODULE_CONST_FN_PATTERN.finditer(text))
    return {'state': state_vars, 'setters': setters, 'props': props, 'refs': ref_vars, 'module_fns': module_fns}


def extract_params(callback_text):
    header_end = callback_text.find('=>')
    if header_end == -1:
        return []
    header = callback_text[:header_end].replace('async', '').strip()
    if not header:
        return []
    if header.startswith('(') and header.endswith(')'):
        header = header[1:-1]
    params = []
    for raw in header.split(','):
        token = raw.strip()
        if not token:
            continue
        name = token.split('=')[0].strip()
        if name.startswith('{') and name.endswith('}'):
            params.extend(parse_props(name[1:-1]))
        elif name:
            params.append(name)
    return params


def extract_locals(callback_text):
    locals_set = {m.group(1) for m in re.finditer(r"(?:const|let|var|function)\s+([A-Za-z_][A-Za-z0-9_]*)", callback_text)}
    for match in re.finditer(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*=>", callback_text):
        locals_set.add(match.group(1))
    for match in re.finditer(r"\(\s*([^)]+?)\s*\)\s*=>", callback_text):
        locals_set.update(parse_props(match.group(1)))
    # GH #93: `catch (err)` bindings are callback-local, not render-scope
    # values — never suggest them as hook dependencies.
    for match in re.finditer(r"catch\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)", callback_text):
        locals_set.add(match.group(1))
    return locals_set


def strip_template_literals(text):
    result = []
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch == '`':
            i += 1
            while i < length:
                if text[i] == '\\' and i + 1 < length:
                    i += 2
                    continue
                if text[i] == '$' and i + 1 < length and text[i + 1] == '{':
                    i += 2
                    brace = 1
                    while i < length and brace:
                        if text[i] == '{':
                            brace += 1
                        elif text[i] == '}':
                            brace -= 1
                        if brace == 0:
                            i += 1
                            break
                        result.append(text[i])
                        i += 1
                    continue
                if text[i] == '`':
                    i += 1
                    break
                i += 1
            continue
        result.append(ch)
        i += 1
    return ''.join(result)


def strip_strings(text):
    text = STRING_RE.sub(' ', text)
    return strip_template_literals(text)


def strip_comments(text):
    return COMMENT_RE.sub(' ', text)


def extract_identifiers(callback_text):
    cleaned = strip_comments(strip_strings(callback_text))
    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cleaned))


def parse_deps(text):
    text = text.strip()
    if not (text.startswith('[') and text.endswith(']')):
        return []
    inner = text[1:-1]
    out, buf, depth = [], [], 0
    for ch in inner:
        if ch == ',' and depth == 0:
            token = ''.join(buf).strip()
            if token:
                out.append(token)
            buf = []
            continue
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(depth - 1, 0)
        buf.append(ch)
    token = ''.join(buf).strip()
    if token:
        out.append(token)
    return out


def classify(name, symbols):
    if name in symbols['props']:
        return 'prop'
    if name in symbols['state']:
        return 'state'
    if name in symbols['refs']:
        return 'ref'
    return 'other'


def skip_name(name, symbols):
    if name in symbols['setters']:
        return True
    if name in symbols.get('module_fns', set()):
        return True
    if name in BUILTINS:
        return True
    if name.startswith('set') and len(name) > 3 and name[3].isupper():
        return True
    return False


def is_literal(dep):
    dep = dep.strip()
    if not dep:
        return True
    if dep[0].isdigit() or dep[0] in '\"\'' or dep in {'true', 'false', 'null', 'undefined'}:
        return True
    return False


def is_unstable(dep):
    dep = dep.strip()
    if not dep:
        return False
    if dep.startswith('{') and dep.endswith('}'):
        return True
    if dep.startswith('[') and dep.endswith(']'):
        return True
    if dep.startswith('(') and '=>' in dep:
        return True
    if dep.startswith('function'):
        return True
    return False


def calc_line(text, start_line, name):
    # Verbatim, doubled backslashes included: the pattern only matches a
    # literal `\b<name>\b` sequence, so in practice the fallback line
    # (callback start + 1) is what legacy reports for every missing dep.
    pattern = re.compile(rf"\\b{re.escape(name)}\\b")
    for offset, line in enumerate(text.splitlines()):
        if pattern.search(line):
            return start_line + offset + 1
    return start_line + 1


def iter_source_issues(text: str, symbols: dict) -> Iterator[tuple[str, int, int, str, str]]:
    """One (rule, line, col, severity, message) per legacy aggregator issue,
    in file order (names within a hook are sorted for determinism; the
    heredoc iterated an unordered set)."""
    for hook_line0, hook_col1, callback, callback_start0, deps_text in find_hook_calls(text):
        if deps_text is None:
            yield (RULE_NO_DEPS, hook_line0 + 1, hook_col1, SEVERITIES[RULE_NO_DEPS], NO_DEPS_MESSAGE)
            continue
        deps_strip = deps_text.strip()
        if not (deps_strip.startswith('[') and deps_strip.endswith(']')):
            continue  # legacy: with-deps match whose DEPS is not an array
        deps = parse_deps(deps_text)
        identifiers = extract_identifiers(callback)
        identifiers -= KEYWORDS
        identifiers -= BUILTINS
        identifiers -= extract_locals(callback)
        identifiers -= set(extract_params(callback))
        for name in sorted(identifiers):
            if skip_name(name, symbols) or is_literal(name):
                continue
            if name not in deps:
                kind = classify(name, symbols)
                rule = RULE_MISSING_CRITICAL if kind == 'prop' else RULE_MISSING_WARNING
                yield (rule, calc_line(callback, callback_start0, name), 1,
                       SEVERITIES[rule], f"Add {name} to the dependency array")
        unused = []
        identifiers_lower = {n.strip() for n in identifiers}
        for dep in deps:
            dep_clean = dep.strip()
            if not dep_clean or is_literal(dep_clean):
                continue
            if dep_clean not in identifiers_lower:
                unused.append(dep_clean)
            if is_unstable(dep_clean):
                yield (RULE_UNSTABLE, hook_line0 + 1, hook_col1, SEVERITIES[RULE_UNSTABLE],
                       f"{dep_clean} changes identity every render; memoize it")
        if unused:
            yield (RULE_UNUSED, hook_line0 + 1, hook_col1, SEVERITIES[RULE_UNUSED],
                   f"Unused dependencies: {', '.join(sorted(set(unused)))}")


def scan_file_findings(path: Path) -> Iterator[dict]:
    """Yield finding records (sans path) for one file; legacy match logic."""
    try:
        raw = path.read_bytes()
    except Exception:
        return
    try:
        text = raw.decode("utf-8")  # heredoc read strictly...
    except UnicodeDecodeError:
        text = ""                   # ...and analysed undecodable files with empty symbols
    symbols = get_file_symbols(text)
    if not text:
        text = raw.decode("utf-8", "ignore")
    for rule, line, col, severity, message in iter_source_issues(text, symbols):
        yield {
            "rule": rule,
            "category_id": CATEGORY_ID,
            "line": line,
            "col": col,
            "severity": severity,
            "message": message,
        }


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        # mirror the heredoc's skip_dirs relative to the scan root (cwd)
        try:
            rel_parts = path.resolve().relative_to(cwd).parts
        except ValueError:
            rel_parts = ()
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        try:
            rel = path.resolve().relative_to(cwd)
        except ValueError:
            rel = path.name
        for finding in scan_file_findings(path):
            record = dict(finding)
            record["path"] = str(rel)
            yield record


# ─────────────────────────────────────────────────────────────────────────────
# Self tests
# ─────────────────────────────────────────────────────────────────────────────
_BUGGY_FIXTURE = """import { useCallback, useEffect, useMemo, useState } from 'react';

export function BuggyHooks({ userId, theme }) {
  const [count, setCount] = useState(0);
  const config = { userId, theme };

  useEffect(() => {
    fetch(`/api/users/${userId}`);
  }, []);

  const handleClick = useCallback(() => {
    console.log(theme, count);
  }, []);

  const memoizedConfig = useMemo(() => ({ config }), [config]);

  useEffect(() => {
    console.log('apply', memoizedConfig);
  }, [memoizedConfig]);
}
"""

_CLEAN_FIXTURE = """import { useCallback, useEffect, useMemo, useState } from 'react';

export function CleanHooks({ userId, theme, signal }) {
  const [count, setCount] = useState(0);
  const memoizedConfig = useMemo(() => ({ userId, theme }), [userId, theme]);

  useEffect(() => {
    fetch(`/api/users/${userId}`, { signal });
  }, [userId, signal]);

  const handleClick = useCallback(() => {
    console.log(theme, count);
    setCount((value) => value + 1);
  }, [theme, count]);

  useEffect(() => {
    console.log('apply', memoizedConfig);
  }, [memoizedConfig]);
}
"""


def _findings_text(src: str, tmp_prefix: str, suffix: str = ".jsx") -> list[dict]:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / f"widget{suffix}"
        target.write_text(src, encoding="utf-8")
        return list(scan_file_findings(target))


def _selftest_buggy_fixture_parity(tmp_prefix: str = "ubs_core_spec_hooks_buggy_") -> None:
    findings = _findings_text(_BUGGY_FIXTURE, tmp_prefix)
    expected = {
        (RULE_MISSING_CRITICAL, 7, "Add userId to the dependency array"),
        (RULE_MISSING_CRITICAL, 11, "Add theme to the dependency array"),
        (RULE_MISSING_WARNING, 11, "Add count to the dependency array"),
    }
    got = {(f["rule"], f["line"], f["message"]) for f in findings}
    assert got == expected, findings
    assert all(f["severity"] == SEVERITIES[f["rule"]] for f in findings), findings


def _selftest_clean_fixture(tmp_prefix: str = "ubs_core_spec_hooks_clean_") -> None:
    assert _findings_text(_CLEAN_FIXTURE, tmp_prefix) == []


def _selftest_no_deps(tmp_prefix: str = "ubs_core_spec_hooks_nodeps_") -> None:
    src = "function Panel({ id }) {\n  useEffect(() => {\n    load(id);\n  });\n  const build = useMemo(makeThing);\n  return build;\n}\n"
    findings = _findings_text(src, tmp_prefix)
    assert len(findings) == 2, findings
    for finding in findings:
        assert finding["rule"] == RULE_NO_DEPS, finding
        assert finding["severity"] == "warning", finding
        assert finding["message"] == NO_DEPS_MESSAGE, finding
    assert {f["line"] for f in findings} == {2, 5}, findings


def _selftest_unstable_and_unused(tmp_prefix: str = "ubs_core_spec_hooks_unstable_") -> None:
    src = (
        "const opts = { a: 1 };\n"
        "const extra = 2;\n"
        "function Widget() {\n"
        "  useEffect(() => {\n"
        "    track(opts, ghost);\n"
        "  }, [opts, { fresh }, extra]);\n"
        "}\n"
    )
    got = {(f["rule"], f["line"], f["message"]) for f in _findings_text(src, tmp_prefix)}
    # The bare `track(...)` call is a missing dependency too (only BUILTINS
    # are exempt), and every sample lands on the callback's first line (the
    # verbatim calc_line quirk) / the hook line for dep-entry findings.
    assert got == {
        (RULE_MISSING_WARNING, 4, "Add ghost to the dependency array"),
        (RULE_MISSING_WARNING, 4, "Add track to the dependency array"),
        (RULE_UNSTABLE, 4, "{ fresh } changes identity every render; memoize it"),
        (RULE_UNUSED, 4, "Unused dependencies: extra, { fresh }"),
    }, got


def _selftest_ignore_not_applied(tmp_prefix: str = "ubs_core_spec_hooks_ign_") -> None:
    # The legacy hooks pipeline has no ubs:ignore handling — pin that port.
    src = "useEffect(() => {\n  send(userId); // ubs:ignore\n}, []);\n// ubs:ignore\nuseCallback(() => log(userId), []);\n"
    findings = _findings_text(src, tmp_prefix)
    assert len(findings) == 3, findings
    assert all(f["rule"] == RULE_MISSING_WARNING for f in findings), findings
    assert {(f["line"], f["message"].split()[1]) for f in findings} == {
        (1, "send"), (1, "userId"), (5, "userId"),
    }, findings


def _selftest_non_calls_ignored(tmp_prefix: str = "ubs_core_spec_hooks_noncall_") -> None:
    src = "\n".join([
        "React.useEffect(() => {});",
        "obj.useMemo(build);",
        "const node = new useCallback(fn);",
        "function useEffect(cb) { return cb; }",
        "class Widget { useCallback(fn) { return fn; } }",
        "useEffect(fn, deps, extra);",
        "useEffect(fn, depsVar);",
        "useEffect();",
    ]) + "\n"
    assert _findings_text(src, tmp_prefix) == []


def _selftest_run_record_shape(tmp_prefix: str = "ubs_core_spec_hooks_run_") -> None:
    import tempfile

    from ubs_core.registry import RunContext as Ctx, analyzers_for_lang

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "panel.tsx"
        target.write_text(_BUGGY_FIXTURE, encoding="utf-8")
        analyzer = next(a for a in analyzers_for_lang("javascript") if a.name == "spec_hooks")
        records = list(analyzer.run(Ctx(lang="javascript", files=[target])))
        assert records, records
        for rec in records:
            assert set(rec) == {"rule", "category_id", "path", "line", "col", "severity", "message"}, rec
            assert rec["category_id"] == "js.hooks", rec
            assert rec["severity"] == SEVERITIES[rec["rule"]], rec
            assert rec["path"] == "panel.tsx", rec
            assert rec["rule"].startswith("js.hooks."), rec
        assert {r["severity"] for r in records} == {"critical", "warning"}, records


SELF_TESTS: tuple[tuple[str, object], ...] = (
    ("buggy_fixture_parity", _selftest_buggy_fixture_parity),
    ("clean_fixture", _selftest_clean_fixture),
    ("no_deps", _selftest_no_deps),
    ("unstable_and_unused", _selftest_unstable_and_unused),
    ("ignore_not_applied", _selftest_ignore_not_applied),
    ("non_calls_ignored", _selftest_non_calls_ignored),
    ("run_record_shape", _selftest_run_record_shape),
)

register(Analyzer(layer="regex", lang="javascript", name="spec_hooks", run=run, selftests=SELF_TESTS))
