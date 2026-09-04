"""ubs_core.analyzers.guards_generic — parameterized deep-chain guard analysis (bead D3).

One engine, seven language frontends (bead D3): go, rust, java, csharp, swift,
cpp, elixir. javascript/python/ruby keep their dedicated bead-A2 analyzers
(guards_js / guards_py / guards_ruby) and are NOT registered here.

Calibrated per GH #90: a deep property chain that is reached without an
explicit guard is a defensive-access lint — severity ``warning`` at worst,
never critical. A chain is *guarded* when it appears inside a construct that
demonstrates the access was checked:

* nil/null checks: ``if x != nil`` (go), ``if let Some(x) = x`` / ``let ... else``
  (rust), ``if (x != null)`` / ``Objects.isNull`` / ``instanceof`` (java),
  ``x is null`` / ``IsNullOrEmpty`` (csharp), ``if let`` / ``guard let`` (swift),
  ``nullptr`` / ``NULL`` / truthiness ``if (!p)`` (cpp), ``is_nil(x)`` (elixir);
* short-circuit conditions: chains inside the condition of such an if/while;
* ternaries: ``x != null ? x.a.b.c.d : fallback`` (java/csharp/cpp/swift);
* early-exit guards: ``if (x != nil) { return ... }`` / ``guard ... else`` /
  ``let Some(x) = ... else`` suppress chains on the same root for the rest of
  the enclosing block (the canonical go/java/cpp nil-check idiom);
* dispatch constructs: ``match``/``switch``/``case``/``with`` heads that name
  the root guard every chain inside the block (GH #90's membership-guard
  rationale: flagging a pattern dispatch teaches people to delete guards).

Chains are plain-text spans of four separator-joined segments (``a.b.c.d``; cpp
also ``p->a->b->c``, mixed ``a.b->c.d``; swift/csharp force-unwrap and
null-forgiving ``a!.b!.c!.d``), scanned on comment/string-masked text so
offsets match the original source. Safe-navigation chains (``a?.b?.c?.d`` and
elixir ``a&.b``) never become candidates — the access is already guarded by
construction, exactly like guards_ruby's ``&.`` handling. Guard regions are
*root-scoped*: ``if (user != nil) { data.a.b.c.d }`` still reports ``data``.

``run(ctx)`` yields ``<lang>.guards.unguarded_chain`` findings (path/line/col/
message) for the ``python3 -m ubs_core guards --lang <lang>`` CLI.
"""
from __future__ import annotations

import itertools
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator

from ubs_core.io import find_block_end, line_col
from ubs_core.lexer import strip_comments_and_strings
from ubs_core.registry import Analyzer, RunContext, register

SEVERITY = "warning"  # GH #90: defensive-access lint — warning at worst
MESSAGE = (
    "Deep property chain without an explicit guard "
    "(nil/null check, if let/guard, ternary, case/switch dispatch, or safe navigation)"
)

_MAX_HEADER = 800  # sanity cap: distance from guard keyword to its opening brace

# Root-scoped guard regions are keyed on these identifiers; keywords and
# null literals can never root a chain the guard covers.
_ROOT_EXCLUDE = frozenset({
    "nil", "null", "nullptr", "NULL", "None", "Some", "Ok", "Err",
    "true", "false", "True", "False", "TRUE", "FALSE",
    "this", "self", "Self", "base", "super",
    "if", "else", "while", "for", "guard", "match", "switch", "when",
    "do", "end", "fn", "with", "cond", "unless", "case",
    "let", "var", "const", "final", "new", "is", "not", "in", "as",
    "return", "throw", "raise",
})

# dispatch constructs guard their whole block regardless of root (see docstring)
_DISPATCH_KWS = frozenset({"match", "switch", "case", "with", "cond"})

_IDENT_RE = re.compile(r"(?<![\w$.@>])([A-Za-z_]\w*)")
_TRUTHINESS_RE = re.compile(r"!?\s*[A-Za-z_]\w*")

_DOT_CHAIN_TAIL = r"(?:\.[A-Za-z_]\w*){3}"
_CHAIN_DOT = re.compile(r"(?<![\w$.@])([A-Za-z_]\w*)" + _DOT_CHAIN_TAIL)
_CHAIN_CPP = re.compile(r"(?<![\w$.@>])([A-Za-z_]\w*)(?:(?:\.|->)[A-Za-z_]\w*){3}")
_CHAIN_BANG = re.compile(r"(?<![\w$.@])([A-Za-z_]\w*)(?:(?:\.|!\.)[A-Za-z_]\w*){3}")

_HEADER_PAREN_RE = re.compile(r"\b(if|while|for|switch)\s*\(")
_HEADER_BRACE_RE = re.compile(r"\b(if|while|for|guard|match|switch)\b")
_KW_HEADER_RE = re.compile(r"(?:if|while|for|switch|guard|match)\b")
_ELX_HEADER_RE = re.compile(r"\b(if|unless|case|with|cond)\b")
_LET_SOME_RE = re.compile(r"\blet\s+(?:Some|Ok)\s*\(")
_DO_TOKEN_RE = re.compile(r"\b(?:fn|do|end)\b(?!:)")


@dataclass(frozen=True)
class LangSpec:
    """Per-language frontend for the shared deep-chain guard engine."""

    lang: str                                # registry lang id
    name: str                                # analyzer name (unique per layer/lang)
    exts: frozenset                          # file suffixes (lowercase)
    style: str                               # "paren" | "brace" | "do_end"
    chain_re: re.Pattern                     # deep-chain candidates (group 1 = root)
    null_re: re.Pattern                      # null-check predicate tokens
    early_exit_re: re.Pattern | None         # body keywords enabling early-exit guards
    ternary: bool = False                    # language has `?:` guards
    truthiness: bool = False                 # bare `if (p)` / `if (!p)` counts as a null check
    let_else: bool = False                   # rust `let Some(x) = e else { ... }`
    import_re: re.Pattern | None = None      # lines never to flag (import/package/using/...)
    strip_lang: str = "c_like"               # ubs_core.lexer mask dialect
    prep: Callable[[str], str] | None = None  # pre-mask hook (rust lifetimes)
    sample_buggy: str = ""                   # self-test inputs
    sample_guarded: str = ""


def _mask_lifetimes(text: str) -> str:
    """Blank rust lifetime/label ticks so the c_like masker never eats source.

    ``'a`` followed by anything but a quote is a lifetime or loop label, not a
    char literal; masking it to spaces keeps offsets stable for the lexer.
    """
    return re.sub(r"'[A-Za-z_]\w*(?!')", lambda m: " " * len(m.group(0)), text)


def _roots_of(text: str) -> frozenset:
    """Identifiers in `text` that may root a chain (fields `x.y` excluded)."""
    return frozenset(i for i in _IDENT_RE.findall(text) if i not in _ROOT_EXCLUDE)


def _is_null_check(spec: LangSpec, text: str, kw: str) -> bool:
    if kw in _DISPATCH_KWS:
        return True  # dispatching on the value itself is the guard (root-scoped check done by caller)
    if spec.null_re.search(text):
        return True
    if spec.truthiness and _TRUTHINESS_RE.fullmatch(text.strip()):
        return True
    return False


def _skip_ws(text: str, pos: int) -> int:
    n = len(text)
    while pos < n and text[pos] in " \t\r\n":
        pos += 1
    return pos


def _matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _brace_pairs(text: str) -> list:
    pairs, stack = [], []
    for i, ch in enumerate(text):
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            pairs.append((stack.pop(), i))
    return pairs


def _enclosing_block_end(pairs: list, pos: int) -> int:
    """End offset of the innermost brace block containing `pos`, else -1."""
    best = None
    for o, c in pairs:
        if o < pos < c and (best is None or c - o < best[1] - best[0]):
            best = (o, c)
    return best[1] if best else -1


def _consume_stmt(text: str, pos: int) -> int:
    """End offset (exclusive) of the statement starting at/after `pos`.

    Braced blocks consume their balanced block plus any else/else-if chain;
    keyword headers (braceless-body languages keep braces, but `else if` needs
    this) likewise; anything else runs to the first `;` at bracket depth 0.
    """
    pos = _skip_ws(text, pos)
    if pos >= len(text):
        return pos
    if text[pos] == "{":
        return find_block_end(text, pos) + 1
    if _KW_HEADER_RE.match(text, pos):
        brace = text.find("{", pos)
        if brace >= 0 and "}" not in text[pos:brace]:
            return _else_chain(text, find_block_end(text, brace) + 1)
    depth = 0
    for i in range(pos, len(text)):
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif ch == ";" and depth == 0:
            return i + 1
    return len(text)


def _else_chain(text: str, end: int) -> int:
    """Extend past `else ...` / `else if ...` continuations of a statement."""
    while True:
        j = _skip_ws(text, end)
        if text.startswith("else", j):
            k = j + 4
            if k >= len(text) or not (text[k].isalnum() or text[k] == "_"):
                end = _consume_stmt(text, k)
                continue
        return end


def _match_do_end(stripped: str, do_pos: int) -> int:
    """Index of the `end` closing the block opened by `do` at `do_pos`."""
    depth = 1
    for m in _DO_TOKEN_RE.finditer(stripped, do_pos + 2):
        if m.group() == "end":
            depth -= 1
            if depth == 0:
                return m.start()
        else:
            depth += 1
    return max(0, len(stripped) - 1)


def _paren_regions(spec: LangSpec, stripped: str, pairs: list, regions: list) -> None:
    """if/while/for/switch (...) guards — java, csharp, cpp."""
    for m in _HEADER_PAREN_RE.finditer(stripped):
        kw = m.group(1)
        open_idx = m.end() - 1
        close = _matching_paren(stripped, open_idx)
        if close < 0:
            continue
        cond = stripped[open_idx + 1:close]
        roots = _roots_of(cond)
        if not roots or not _is_null_check(spec, cond, kw):
            continue
        bpos = _skip_ws(stripped, close + 1)
        if bpos < len(stripped) and stripped[bpos] == "{":
            bend = find_block_end(stripped, bpos) + 1
        else:
            bend = _consume_stmt(stripped, bpos)
        stmt_end = _else_chain(stripped, bend)
        if kw in _DISPATCH_KWS:
            regions.append((m.start(), stmt_end, None))
            continue
        regions.append((open_idx, close + 1, roots))  # chains inside the condition
        regions.append((bpos, bend, roots))           # the guarded body
        if stmt_end > bend:                           # else branch of the same check
            regions.append((bend, stmt_end, roots))
        if spec.early_exit_re is not None and spec.early_exit_re.search(stripped[bpos:bend]):
            eff_end = _enclosing_block_end(pairs, m.start())
            if eff_end > stmt_end:
                regions.append((stmt_end, eff_end, roots))


def _brace_regions(spec: LangSpec, stripped: str, pairs: list, regions: list) -> None:
    """if/while/for/guard/match/switch ... { } guards — go, rust, swift."""
    for m in _HEADER_BRACE_RE.finditer(stripped):
        kw = m.group(1)
        brace = stripped.find("{", m.end())
        if brace < 0 or brace - m.start() > _MAX_HEADER:
            continue
        header = stripped[m.start():brace]
        if "}" in header:
            continue
        roots = _roots_of(header)
        if not roots or not _is_null_check(spec, header, kw):
            continue
        bend = find_block_end(stripped, brace) + 1
        stmt_end = _else_chain(stripped, bend)
        if kw in _DISPATCH_KWS:
            regions.append((m.start(), stmt_end, None))
            continue
        regions.append((m.start(), stmt_end, roots))
        if kw == "guard" or (spec.early_exit_re is not None
                             and spec.early_exit_re.search(stripped[brace:bend])):
            eff_end = _enclosing_block_end(pairs, m.start())
            if eff_end > stmt_end:
                regions.append((stmt_end, eff_end, roots))


def _do_end_regions(spec: LangSpec, stripped: str, regions: list) -> None:
    """if/unless/case/with/cond ... do ... end guards — elixir."""
    for m in _ELX_HEADER_RE.finditer(stripped):
        kw = m.group(1)
        line_end = stripped.find("\n", m.start())
        if line_end < 0:
            line_end = len(stripped)
        head_zone = stripped[m.start():line_end]
        dm = re.search(r",\s*do:", head_zone)
        if dm:  # one-line keyword-list form: region is the physical line
            head = head_zone[:dm.start()]
            roots = _roots_of(head)
            if roots and _is_null_check(spec, head, kw):
                regions.append((m.start(), line_end, None if kw in _DISPATCH_KWS else roots))
            continue
        dm = re.search(r"\bdo\b(?!:)", head_zone)
        if dm:
            do_pos = m.start() + dm.start()
        else:  # multi-line head (e.g. `with` clauses): first block `do` after the keyword
            fwd = re.search(r"\bdo\b(?!:)", stripped[m.end():])
            if not fwd:
                continue
            do_pos = m.end() + fwd.start()
        end_pos = _match_do_end(stripped, do_pos)
        head = stripped[m.start():do_pos]
        roots = _roots_of(head)
        if roots and _is_null_check(spec, head, kw):
            regions.append((m.start(), end_pos + 3, None if kw in _DISPATCH_KWS else roots))


def _ternary_regions(spec: LangSpec, stripped: str, regions: list) -> None:
    """`cond ? then : else` guards — java, csharp, cpp, swift (GH #90 ternaries)."""
    for m in re.finditer(r"\?(?![?.])", stripped):
        q = m.start()
        if q > 0 and stripped[q - 1] == "?":
            continue  # the tail of a ?? coalescing operator
        start = _expr_start(stripped, q)
        cond = stripped[start:q]
        roots = _roots_of(cond)
        if not roots or not _is_null_check(spec, cond, "if"):
            continue
        regions.append((start, _ternary_end(stripped, q), roots))


def _expr_start(text: str, q: int) -> int:
    """Start of the expression ending just before a `?` (guards_js dialect)."""
    depth = 0
    i = q - 1
    while i >= 0:
        ch = text[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                return i + 1
            depth -= 1
        elif depth == 0 and ch in ";,{}:":
            return i + 1
        i -= 1
    return 0


def _ternary_end(text: str, q: int) -> int:
    """End of the ternary starting at `?`: after its alternate branch."""
    n = len(text)
    depth = 0
    i = q + 1
    while i < n:
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0:
            if ch == "?" and i + 1 < n and text[i + 1] == "?":
                i += 1
            elif ch == ";":
                return i
        i += 1
    return n


def _let_else_regions(spec: LangSpec, stripped: str, pairs: list, regions: list) -> None:
    """rust `let Some(x) = e else { ... };` — the whole tail of the block is guarded."""
    for m in _LET_SOME_RE.finditer(stripped):
        semi = stripped.find(";", m.start())
        if semi < 0:
            continue
        seg = stripped[m.start():semi]
        em = re.search(r"\belse\s*\{", seg)
        if not em:
            continue
        cb = find_block_end(stripped, m.start() + em.end() - 1) + 1
        roots = _roots_of(seg[:em.start()])
        if not roots:
            continue
        regions.append((m.start(), cb, roots))
        eff_end = _enclosing_block_end(pairs, m.start())
        if eff_end > cb:
            regions.append((cb, eff_end, roots))


def _guard_regions(spec: LangSpec, stripped: str) -> list:
    """All guard regions for one file: (start, end, roots-or-None) offsets."""
    regions: list = []
    pairs = _brace_pairs(stripped)
    if spec.style == "paren":
        _paren_regions(spec, stripped, pairs, regions)
    elif spec.style == "brace":
        _brace_regions(spec, stripped, pairs, regions)
    else:
        _do_end_regions(spec, stripped, regions)
    if spec.ternary:
        _ternary_regions(spec, stripped, regions)
    if spec.let_else:
        _let_else_regions(spec, stripped, pairs, regions)
    return regions


def _is_guarded(start: int, end: int, root: str, regions: list) -> bool:
    for s, e, roots in regions:
        if s <= start and end <= e and (roots is None or root in roots):
            return True
    return False


def _make_run(spec: LangSpec) -> Callable[[RunContext], Iterable[dict]]:
    def run(ctx: RunContext) -> Iterator[dict]:
        cwd = Path.cwd()
        for path in ctx.files:
            if path.suffix.lower() not in spec.exts:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if spec.prep is not None:
                text = spec.prep(text)
            stripped = strip_comments_and_strings(text, lang=spec.strip_lang)
            regions = _guard_regions(spec, stripped)
            for m in spec.chain_re.finditer(stripped):
                if spec.import_re is not None:
                    line_start = stripped.rfind("\n", 0, m.start()) + 1
                    if spec.import_re.match(stripped, line_start):
                        continue  # import/package/using lines are never chains
                root = m.group(1)
                if _is_guarded(m.start(), m.end(), root, regions):
                    continue
                line, col = line_col(text, m.start())
                try:
                    rel = str(path.relative_to(cwd))
                except ValueError:
                    rel = str(path)
                yield {
                    "rule": f"{spec.lang}.guards.unguarded_chain",
                    "path": rel,
                    "line": line,
                    "col": col,
                    "layer": "guards",
                    "lang": spec.lang,
                    "severity": SEVERITY,
                    "message": MESSAGE,
                }

    return run


# ────────────────────────────────────────────────────────────────────────────
# Language frontends
# ────────────────────────────────────────────────────────────────────────────

SPECS: tuple = (
    LangSpec(
        lang="go",
        name="guards_go",
        exts=frozenset({".go"}),
        style="brace",
        chain_re=_CHAIN_DOT,
        null_re=re.compile(r"\bnil\b"),
        early_exit_re=re.compile(
            r"\b(?:return|break|continue|goto)\b|\bpanic\s*\(|\bos\.Exit\s*\(|\blog\.(?:Fatal\w*)\s*\("),
        import_re=re.compile(r"[ \t]*(?:import|package)\b"),
        sample_buggy=(
            "package inventory\n"
            "\n"
            "func Total(resp *CatalogResponse) int {\n"
            "\treturn resp.Catalog.Page.Items.Total\n"
            "}\n"
        ),
        sample_guarded=(
            "package inventory\n"
            "\n"
            "func Total(resp *CatalogResponse) int {\n"
            "\tif resp == nil || resp.Catalog == nil {\n"
            "\t\treturn 0\n"
            "\t}\n"
            "\treturn resp.Catalog.Page.Items.Total\n"
            "}\n"
            "\n"
            "func TotalOr(resp *CatalogResponse) int {\n"
            "\tif resp != nil {\n"
            "\t\treturn resp.Catalog.Page.Items.Total\n"
            "\t}\n"
            "\treturn 0\n"
            "}\n"
        ),
    ),
    LangSpec(
        lang="rust",
        name="guards_rust",
        exts=frozenset({".rs"}),
        style="brace",
        chain_re=_CHAIN_DOT,
        null_re=re.compile(r"\bNone\b|\bSome\s*\(|\bOk\s*\(|\.is_(?:some|none|ok|err)\s*\("),
        early_exit_re=re.compile(
            r"\b(?:return|break|continue)\b|panic!\s*|unreachable!\s*|todo!\s*|process::exit"),
        let_else=True,
        import_re=re.compile(r"[ \t]*(?:pub\s+)?(?:use|extern\s+crate|mod)\b"),
        prep=_mask_lifetimes,
        sample_buggy=(
            "pub fn total(config: &Config) -> u64 {\n"
            "    config.runtime.limits.teams.max\n"
            "}\n"
        ),
        sample_guarded=(
            "pub fn total(config: Option<&Config>) -> u64 {\n"
            "    let Some(config) = config else {\n"
            "        return 0;\n"
            "    };\n"
            "    config.runtime.limits.teams.max\n"
            "}\n"
            "\n"
            "pub fn total2(config: Option<&Config>) -> u64 {\n"
            "    if let Some(config) = config {\n"
            "        return config.runtime.limits.teams.max;\n"
            "    }\n"
            "    0\n"
            "}\n"
        ),
    ),
    LangSpec(
        lang="java",
        name="guards_java",
        exts=frozenset({".java"}),
        style="paren",
        chain_re=_CHAIN_DOT,
        null_re=re.compile(r"\bnull\b|Objects\s*\.\s*(?:isNull|nonNull)\s*\(|\binstanceof\b"),
        early_exit_re=re.compile(r"\b(?:return|break|continue|throw)\b|\bSystem\.exit\s*\("),
        ternary=True,
        import_re=re.compile(r"[ \t]*(?:import|package)\b"),
        sample_buggy=(
            "class OrderTotal {\n"
            "    int total(Customer customer) {\n"
            "        return customer.profile.stats.orders.total;\n"
            "    }\n"
            "}\n"
        ),
        sample_guarded=(
            "class OrderTotal {\n"
            "    int total(Customer customer) {\n"
            "        if (customer == null || customer.profile == null) {\n"
            "            return 0;\n"
            "        }\n"
            "        return customer.profile.stats.orders.total;\n"
            "    }\n"
            "\n"
            "    int safeTotal(Customer customer) {\n"
            "        return customer != null ? customer.profile.stats.orders.total : 0;\n"
            "    }\n"
            "}\n"
        ),
    ),
    LangSpec(
        lang="csharp",
        name="guards_csharp",
        exts=frozenset({".cs"}),
        style="paren",
        chain_re=_CHAIN_BANG,
        null_re=re.compile(
            r"\bnull\b|\bIsNullOrEmpty\s*\(|\bIsNullOrWhiteSpace\s*\(|\bis\s+[A-Za-z_]\w*\s+[A-Za-z_]\w*"),
        early_exit_re=re.compile(r"\b(?:return|break|continue|throw)\b|\bEnvironment\.Exit\s*\(|\bgoto\b"),
        ternary=True,
        import_re=re.compile(r"[ \t]*(?:using|namespace)\b"),
        sample_buggy=(
            "class Telemetry {\n"
            "    int TimeoutMs(Config cfg) {\n"
            "        return cfg.Http.Stack.Retry.TimeoutMs;\n"
            "    }\n"
            "}\n"
        ),
        sample_guarded=(
            "class Telemetry {\n"
            "    int TimeoutMs(Config cfg) {\n"
            "        if (cfg is null) {\n"
            "            return 0;\n"
            "        }\n"
            "        return cfg.Http.Stack.Retry.TimeoutMs;\n"
            "    }\n"
            "\n"
            "    int SafeTimeout(Config cfg) {\n"
            "        return cfg?.Http?.Stack?.Retry?.TimeoutMs ?? 0;\n"
            "    }\n"
            "}\n"
        ),
    ),
    LangSpec(
        lang="swift",
        name="guards_swift",
        exts=frozenset({".swift"}),
        style="brace",
        chain_re=_CHAIN_BANG,
        null_re=re.compile(r"\bnil\b|\blet\s"),
        early_exit_re=re.compile(r"\b(?:return|break|continue|throw)\b|\bfatalError\s*\("),
        ternary=True,
        strip_lang="swift",
        import_re=re.compile(r"[ \t]*import\b"),
        sample_buggy=(
            "func total(_ envelope: Envelope) -> Int {\n"
            "    return envelope.data.metrics.count.total\n"
            "}\n"
        ),
        sample_guarded=(
            "func total(_ envelope: Envelope?) -> Int {\n"
            "    guard let envelope = envelope, envelope.isValid else {\n"
            "        return 0\n"
            "    }\n"
            "    return envelope.data.metrics.count.total\n"
            "}\n"
            "\n"
            "func total2(_ envelope: Envelope?) -> Int {\n"
            "    if let env = envelope {\n"
            "        return env.data.metrics.count.total\n"
            "    }\n"
            "    return 0\n"
            "}\n"
        ),
    ),
    LangSpec(
        lang="cpp",
        name="guards_cpp",
        exts=frozenset({".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"}),
        style="paren",
        chain_re=_CHAIN_CPP,
        null_re=re.compile(r"\bnullptr\b|\bNULL\b"),
        early_exit_re=re.compile(
            r"\b(?:return|break|continue|throw)\b|\bexit\s*\(|\babort\s*\(|std::terminate"),
        ternary=True,
        truthiness=True,
        import_re=re.compile(r"[ \t]*#\s*(?:include|import)\b"),
        sample_buggy=(
            "int total(Env* env) {\n"
            "    return env->world.state.count.total;\n"
            "}\n"
        ),
        sample_guarded=(
            "int total(Env* env) {\n"
            "    if (env == nullptr) {\n"
            "        return 0;\n"
            "    }\n"
            "    return env->world.state.count.total;\n"
            "}\n"
            "\n"
            "int depth(World* world) {\n"
            "    if (!world) {\n"
            "        return -1;\n"
            "    }\n"
            "    return world->map.zoom.level.max;\n"
            "}\n"
        ),
    ),
    LangSpec(
        lang="elixir",
        name="guards_elixir",
        exts=frozenset({".ex", ".exs"}),
        style="do_end",
        chain_re=_CHAIN_DOT,
        null_re=re.compile(r"\bnil\b|\bis_nil\s*\("),
        early_exit_re=None,
        strip_lang="elixir",
        import_re=re.compile(r"[ \t]*(?:import|alias|require|use)\b"),
        sample_buggy=(
            "defmodule Inventory do\n"
            "  def total(envelope) do\n"
            "    envelope.data.metrics.count.total\n"
            "  end\n"
            "end\n"
        ),
        sample_guarded=(
            "defmodule Inventory do\n"
            "  def total(envelope) do\n"
            "    case envelope do\n"
            "      nil -> 0\n"
            "      _ -> envelope.data.metrics.count.total\n"
            "    end\n"
            "  end\n"
            "end\n"
            "\n"
            "def total2(envelope) do\n"
            "  if is_nil(envelope) do\n"
            "    0\n"
            "  else\n"
            "    envelope.data.metrics.count.total\n"
            "  end\n"
            "end\n"
        ),
    ),
)

SPEC_BY_LANG = {spec.lang: spec for spec in SPECS}


# ────────────────────────────────────────────────────────────────────────────
# Self-tests: ≥2 per registration (unguarded positive + guard suppression)
# ────────────────────────────────────────────────────────────────────────────

def _run_on(spec: LangSpec, code: str) -> list:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=f"ubs_core_{spec.name}_") as td:
        sample = Path(td) / f"sample{sorted(spec.exts)[0]}"
        sample.write_text(code, encoding="utf-8")
        ctx = RunContext(lang=spec.lang, files=[sample])
        return list(_make_run(spec)(ctx))


def _selftests_for(spec: LangSpec) -> list:
    def unguarded_positive() -> None:
        findings = _run_on(spec, spec.sample_buggy)
        assert findings, (spec.lang, spec.sample_buggy)
        first = findings[0]
        assert first["rule"] == f"{spec.lang}.guards.unguarded_chain", first
        assert first["severity"] == "warning", first  # GH #90: warning at worst
        assert first["layer"] == "guards" and first["lang"] == spec.lang, first
        assert first["line"] >= 1 and first["col"] >= 1, first

    def guard_suppression() -> None:
        findings = _run_on(spec, spec.sample_guarded)
        assert findings == [], (spec.lang, spec.sample_guarded, findings)

    return [
        (f"{spec.name}.unguarded_positive", unguarded_positive),
        (f"{spec.name}.guard_suppression", guard_suppression),
    ]


def _selftest_engine_root_scoping() -> None:
    # Guards are root-scoped: `user` checked, but the chain roots at `data`.
    code = (
        "package main\n"
        "\n"
        "func f(user *U, data *D) int {\n"
        "\tif user != nil {\n"
        "\t\treturn data.a.b.c.d\n"
        "\t}\n"
        "\treturn 0\n"
        "}\n"
    )
    findings = _run_on(SPEC_BY_LANG["go"], code)
    assert len(findings) == 1, findings
    assert findings[0]["line"] == 5, findings[0]


def _selftest_engine_safe_nav_excluded() -> None:
    # Safe-navigation chains are guarded by construction: never candidates.
    code = "class C {\n  int M(Config c) => c?.a?.b?.c?.d ?? 0;\n}\n"
    findings = _run_on(SPEC_BY_LANG["csharp"], code)
    assert findings == [], findings


SELF_TESTS: tuple = (
    ("guards_generic.root_scoping", _selftest_engine_root_scoping),
    ("guards_generic.safe_nav_excluded", _selftest_engine_safe_nav_excluded),
) + tuple(
    itertools.chain.from_iterable(_selftests_for(spec) for spec in SPECS)
)

for _spec in SPECS:
    register(Analyzer(
        layer="guards",
        lang=_spec.lang,
        name=_spec.name,
        run=_make_run(_spec),
        selftests=tuple(_selftests_for(_spec)),
    ))
