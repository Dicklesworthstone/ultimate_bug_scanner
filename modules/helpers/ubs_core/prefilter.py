"""ubs_core.prefilter — Necessary-literal prefilter for ast-grep, patterns, and analyzers (bead C2).

Extracts necessary literal tokens from ast-grep rule packs, regex patterns, and
registered analyzers. Runs ONE ripgrep pass (Aho-Corasick SIMD) over the file
list to compute per-file rule candidate sets. Ast-grep and pattern checks then
run only on candidate files that can match, eliminating 80-95% of ast-grep and
regex overhead on multi-file projects.

Conservative by construction: rules with no extractable literal fall back to
matching all files. UBS_NO_PREFILTER=1 disables prefiltering entirely.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

# Environment variable to disable prefiltering for A/B testing
ENV_NO_PREFILTER = "UBS_NO_PREFILTER"

# Batch size for ripgrep file argument lists (ARG_MAX safety)
_RG_BATCH = 400

# Rules that are explicitly permitted to have an empty literal set across rule packs.
# No rule may extract an empty set silently; any unlisted empty rule fails quality checks.
ALLOWED_EMPTY_RULES: dict[str, set[str]] = {
    "js": {
        "js.async.dangling-promise",
        "async-dangling-promise",
    },
    "py": {
        "py.path-join-plus",  # $A + $B (binary plus expression without keywords)
        "path-join-plus",
    },
    "go": set(),  # All Go rules extract literals (including 'import' for import_spec)
    "java": {
        "java.string-eq-operator",  # $X == $Y or $X != $Y (binary operator without keywords)
        "string-eq-operator",
    },
    "ruby": {
        "rb.mutable-const",  # $CONST = [...] (constant assignment without keywords)
        "mutable-const",
        "rb.float-eq",       # $X == 0.0 (float comparison)
        "float-eq",
    },
    "rust": {
        "rust.ast.direct_index",  # $X[$I] (slice/array index without keywords)
        "direct_index",
    },
    "csharp": set(),  # All 4 C# rules extract literals
    "swift": set(),   # All Swift rules extract literals
}

# Known necessary literals for common analyzer families
ANALYZER_LITERALS: dict[str, set[str]] = {
    "sec_jwt": {"jwt", "jsonwebtoken", "ParseUnverified", "decode", "verify", "JWT"},
    "sec_archive_entry": {"zip", "tar", "extract", "unzip", "Archive", "ZipFile", "TarFile"},
    "sec_cookies": {"cookie", "Set-Cookie", "cookieParser", "session", "sameSite"},
    "sec_cors": {"cors", "Access-Control-Allow-Origin", "origin"},
    "sec_dangerous_html": {"dangerouslySetInnerHTML", "innerHTML", "outerHTML", "document.write"},
    "sec_fetch_abort": {"fetch", "AbortController", "signal", "timeout"},
    "sec_hardcoded_secrets": {"password", "secret", "token", "apiKey", "api_key", "bearer", "passwd"},
    "sec_header_injection": {"setHeader", "header", "writeHead", "Response", "NextResponse", "headers"},
    "sec_host_header": {"host", "x-forwarded-host", "getHeader"},
    "sec_jsx_target_blank": {"target=\"_blank\"", "target='_blank'", "target=_blank", "_blank"},
    "sec_open_redirect": {"redirect", "Location", "location.href", "sendRedirect"},
    "sec_path_traversal": {"readFile", "readFileSync", "createReadStream", "join", "resolve", "send_file"},
    "sec_post_message": {"postMessage", "addEventListener"},
    "sec_request_body": {"body", "bodyParser", "json", "urlencoded"},
    "sec_request_regex": {"RegExp", "test", "exec", "match"},
    "sec_reverse_proxy": {"createProxyMiddleware", "createProxyServer", "httpProxy", "rewrite", "x-forwarded-for"},
    "sec_sql_injection": {"SELECT", "INSERT", "UPDATE", "DELETE", "query", "execute", "sql", "WHERE"},
    "sec_ssrf_fetch": {"fetch", "axios", "http.get", "https.get", "request"},
    "sec_tls": {"rejectUnauthorized", "NODE_TLS_REJECT_UNAUTHORIZED", "insecure", "tls"},
    "sec_weak_random": {"Math.random", "randomUUID", "randomBytes", "getRandomValues", "randomInt"},
}


@dataclass(frozen=True)
class RuleSpec:
    """Specification of a rule's necessary literal requirements."""
    rule_id: str
    literals: frozenset[str]
    is_fallback: bool
    category: int | None = None
    kind: str = "ast"  # "ast", "pattern", "analyzer"


@dataclass
class PrefilterIndex:
    """Inverted index of necessary literals to rule IDs."""
    rules: dict[str, RuleSpec] = field(default_factory=dict)
    literal_to_rules: dict[str, set[str]] = field(default_factory=dict)  # lowercased literal -> set of rule_ids
    fallback_rules: set[str] = field(default_factory=set)
    all_literals: list[str] = field(default_factory=list)
    ast_rule_ids: set[str] = field(default_factory=set)
    pattern_rule_ids: set[str] = field(default_factory=set)
    analyzer_rule_ids: set[str] = field(default_factory=set)
    has_ast_fallback: bool = False
    expanded_rules: dict[str, set[str]] = field(default_factory=dict)

    def add_rule(self, spec: RuleSpec) -> None:
        self.rules[spec.rule_id] = spec
        if spec.kind == "ast":
            self.ast_rule_ids.add(spec.rule_id)
        elif spec.kind == "pattern":
            self.pattern_rule_ids.add(spec.rule_id)
        elif spec.kind == "analyzer":
            self.analyzer_rule_ids.add(spec.rule_id)

        if spec.is_fallback or not spec.literals:
            self.fallback_rules.add(spec.rule_id)
            if spec.kind == "ast":
                self.has_ast_fallback = True
        else:
            for lit in spec.literals:
                lit_norm = lit.lower()
                self.literal_to_rules.setdefault(lit_norm, set()).add(spec.rule_id)

        self.all_literals = sorted(self.literal_to_rules.keys())

    def finalize(self) -> None:
        """Sort literals longest-first and precompute expanded rule containment."""
        self.all_literals = sorted(self.literal_to_rules.keys(), key=lambda x: (-len(x), x))
        self.expanded_rules = {}
        for lit in self.all_literals:
            s = set(self.literal_to_rules.get(lit, set()))
            for other in self.all_literals:
                if other != lit and other in lit:
                    s.update(self.literal_to_rules.get(other, set()))
            self.expanded_rules[lit] = s


@dataclass
class PrefilterResult:
    """Result of running the ripgrep prefilter pass over files."""
    files_considered: int
    files_after_prefilter: int
    prefilter_ms: int
    file_candidate_rules: dict[str, set[str]] = field(default_factory=dict)  # str(path) -> set of rule_ids
    ast_files: list[Path] = field(default_factory=list)
    is_bypass: bool = False
    index: PrefilterIndex | None = None

    @property
    def candidate_files(self) -> list[str]:
        return [p for p, r in self.file_candidate_rules.items() if r]

    def candidate_rules_for(self, path: Path | str) -> set[str]:
        """Return candidate rule IDs for a given file path."""
        p_str = str(path)
        if self.is_bypass:
            return set(self.index.rules.keys()) if self.index else set()
        fallback = self.index.fallback_rules if self.index else set()
        res = self.file_candidate_rules.get(p_str)
        if res is None:
            try:
                res = self.file_candidate_rules.get(str(Path(path).resolve()))
            except Exception:
                res = None
        return (res if res is not None else set()) | fallback

    def filter_patterns(self, path: Path | str, patterns: Sequence[Any]) -> list[Any]:
        """Filter a list of Pattern objects to only those that can match path."""
        if self.is_bypass:
            return list(patterns)
        candidates = self.candidate_rules_for(path)
        return [p for p in patterns if getattr(p, "rule_id", "") in candidates]

    def should_scan_ast(self, path: Path | str) -> bool:
        """Return True if path contains any candidate AST-grep rules."""
        if self.is_bypass or (self.index and self.index.has_ast_fallback):
            return True
        candidates = self.candidate_rules_for(path)
        ast_ids = self.index.ast_rule_ids if self.index else set()
        return bool(candidates & ast_ids)

    def filter_files_for_analyzer(self, analyzer_name: str, files: Sequence[Path]) -> list[Path]:
        """Filter files to only those that can match a registered analyzer."""
        if self.is_bypass:
            return list(files)
        if not self.index or analyzer_name in self.index.fallback_rules or analyzer_name not in self.index.rules:
            return list(files)
        return [p for p in files if analyzer_name in self.candidate_rules_for(p)]

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to a dict for metrics/profile reporting."""
        return {
            "files_considered": self.files_considered,
            "files_after_prefilter": self.files_after_prefilter,
            "prefilter_ms": self.prefilter_ms,
            "ast_files_count": len(self.ast_files),
            "is_bypass": self.is_bypass,
        }


def extract_ast_rule_literals(rule_id: str, rule_text: str | dict, lang: str = "") -> set[str]:
    """Extract necessary literal strings from an ast-grep rule definition.

    A literal is necessary if ANY match of this rule must contain it in source code.
    If the rule has multiple branches (any:), the rule requires at least one of
    the branch literals. If no necessary literal can be extracted, returns an empty set.
    """
    if isinstance(rule_text, dict):
        text = json.dumps(rule_text)
    else:
        text = str(rule_text)

    # Whitelisted rules that have no keyword literals
    if rule_id in ALLOWED_EMPTY_RULES.get(lang, set()):
        return set()

    literals: set[str] = set()
    lines = text.splitlines()
    in_pattern = False
    in_not = False
    not_indent = 0
    pattern_lines: list[str] = []

    # 1. Parse pattern lines, regex lines, and inline pattern objects
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())

        if in_not:
            if indent > not_indent and stripped:
                continue
            else:
                in_not = False

        if stripped.startswith("- not:") or stripped.startswith("not:"):
            in_not = True
            not_indent = indent
            continue

        if stripped.startswith("- "):
            stripped = stripped[2:].strip()

        # Handle inline mappings: rule: { pattern: "..." }
        inline_m = re.findall(r'pattern:\s*(?:"([^"]+)"|\'([^\']+)\'|([^}\n,]+))', stripped)
        if inline_m:
            for m in inline_m:
                val = (m[0] or m[1] or m[2]).strip()
                if val and val not in ("|", ">-", ">"):
                    pattern_lines.append(val)

        if stripped.startswith("pattern:"):
            val = stripped.split("pattern:", 1)[1].strip()
            if val in ("|", ">-", ">", ""):
                in_pattern = True
            else:
                pattern_lines.append(val)
        elif in_pattern:
            if line.startswith("  ") or line.startswith("\t") or stripped == "":
                if stripped:
                    pattern_lines.append(stripped)
            else:
                in_pattern = False

        if "regex:" in stripped and not in_not:
            val = stripped.split("regex:", 1)[1].strip().strip("\"'")
            cleaned_rg = re.sub(r"\[[^\]]*\]", " ", val)
            words = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", cleaned_rg)
            for w in words:
                if len(w) >= 3 and w.lower() not in ("true", "false", "null", "nil", "none", "undefined", "fetch", "axios"):
                    literals.add(w)

        # Check for kind-specific literals
        if "kind: import_spec" in stripped or "kind: \"import_spec\"" in stripped:
            literals.add("import")

    # 2. Extract tokens from pattern lines
    for p in pattern_lines:
        # Punctuation / operator literals that are very specific in source
        if "??" in p:
            literals.add("??")
        if "!." in p:
            literals.add("!.")
        if "is not" in p:
            literals.add("is not")
        elif " is " in p or p.startswith("is "):
            literals.add("is")
        if "/>" in p:
            literals.add("/>")

        # Dotted expressions (e.g. JSON.parse, Object.assign)
        for d in re.findall(r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*", p):
            literals.add(d)

        # Strip metavariables: $$$ARGS, $VAR, $_
        cleaned = re.sub(r"[$]+[A-Za-z0-9_]*", " ", p)
        # Find identifiers
        words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cleaned)
        for w in words:
            if len(w) >= 2 and w.lower() not in ("true", "false"):
                literals.add(w)

    return literals


def _strip_lookarounds(pat: str) -> str:
    """Strip (?!...) and (?<!...) lookarounds from regex pattern string."""
    res = []
    i = 0
    n = len(pat)
    while i < n:
        if pat[i:i+3] == "(?!" or pat[i:i+4] == "(?<!":
            depth = 1
            i += 3 if pat[i:i+3] == "(?!" else 4
            in_class = False
            while i < n and depth > 0:
                ch = pat[i]
                if ch == "\\":
                    i += 2
                    continue
                if in_class:
                    if ch == "]":
                        in_class = False
                else:
                    if ch == "[":
                        in_class = True
                    elif ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                i += 1
            res.append(" ")
        else:
            res.append(pat[i])
            i += 1
    return "".join(res)


def _extract_regex_literals(regex: Any) -> set[str]:
    if not regex:
        return set()

    pat = regex.pattern if hasattr(regex, "pattern") else str(regex)

    # Normalize single-letter character classes: [Ee] -> e
    pat_norm = re.sub(r"\[([A-Za-z])(?:[A-Za-z])?\]", lambda m: m.group(1).lower(), pat)
    # Strip negative lookaheads / lookbehinds (negative conditions must not be required literals)
    pat_norm = _strip_lookarounds(pat_norm)

    literals: set[str] = set()

    # Top-level alternation: alert|confirm|prompt -> all branches must provide tokens
    parts = pat_norm.split("|")
    if len(parts) > 1 and len(parts) <= 15:
        all_branch_tokens: list[set[str]] = []
        for part in parts:
            cleaned = re.sub(r"\[[^\]]*\]", " ", part)
            cleaned = re.sub(r"\\[bBwWsSdD]", " ", cleaned)
            words = {w.lower() for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,}", cleaned)
                     if w.lower() not in ("true", "false", "null", "nil", "none", "undefined")}
            if words:
                all_branch_tokens.append(words)
        if len(all_branch_tokens) == len(parts):
            # Every branch has tokens: union of branches is necessary
            return set.union(*all_branch_tokens)

    # General regex: extract words of length >= 3 outside character classes
    cleaned = re.sub(r"\[[^\]]*\]", " ", pat_norm)
    cleaned = re.sub(r"\\[bBwWsSdD]", " ", cleaned)
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", cleaned)
    for w in words:
        wl = w.lower()
        if len(wl) >= 3 and wl not in ("true", "false", "null", "nil", "none", "undefined"):
            literals.add(wl)

    return literals


def extract_pattern_literals(pattern: Any) -> set[str]:
    """Extract necessary literal strings from a Pattern object (regex)."""
    if getattr(pattern, "zero_finding", None) is not None:
        return set()

    components = getattr(pattern, "components", ())
    if components:
        all_comp_tokens: list[set[str]] = []
        for comp in components:
            t = _extract_regex_literals(comp)
            if t:
                all_comp_tokens.append(t)
            else:
                return set()
        return set.union(*all_comp_tokens)

    regex = getattr(pattern, "regex", None)
    return _extract_regex_literals(regex)


def build_prefilter_index(
    ast_rules: Sequence[tuple[str, str]] | None = None,
    patterns: Sequence[Any] | None = None,
    analyzers: Sequence[str] | None = None,
    lang: str = "",
) -> PrefilterIndex:
    """Construct a PrefilterIndex from AST rules, patterns, and analyzers."""
    index = PrefilterIndex()

    # 1. AST rules
    if ast_rules:
        for stem, text in ast_rules:
            id_m = re.search(r"id:\s*(\S+)", text)
            rule_id = id_m.group(1) if id_m else stem
            lits = extract_ast_rule_literals(rule_id, text, lang=lang)
            is_fallback = len(lits) == 0
            index.add_rule(RuleSpec(
                rule_id=rule_id,
                literals=frozenset(lits),
                is_fallback=is_fallback,
                kind="ast",
            ))

    # 2. Pattern layer
    if patterns:
        for p in patterns:
            rule_id = getattr(p, "rule_id", "")
            if not rule_id:
                continue
            lits = extract_pattern_literals(p)
            is_fallback = len(lits) == 0
            category = getattr(p, "category", None)
            index.add_rule(RuleSpec(
                rule_id=rule_id,
                literals=frozenset(lits),
                is_fallback=is_fallback,
                category=category,
                kind="pattern",
            ))

    # 3. Analyzers
    if analyzers:
        for aname in analyzers:
            lits = ANALYZER_LITERALS.get(aname, set())
            is_fallback = len(lits) == 0
            index.add_rule(RuleSpec(
                rule_id=aname,
                literals=frozenset(lits),
                is_fallback=is_fallback,
                kind="analyzer",
            ))

    index.finalize()
    return index


def run_prefilter(
    files: Sequence[Path],
    index: PrefilterIndex,
    project_dir: Path | None = None,
) -> PrefilterResult:
    """Execute the ripgrep necessary-literal prefilter pass over files.

    Returns a PrefilterResult with per-file candidate rules and the ast_files subset.
    If UBS_NO_PREFILTER=1 is set, bypasses the filter and treats all files as candidates.
    """
    total_files = len(files)
    if total_files == 0:
        return PrefilterResult(
            files_considered=0,
            files_after_prefilter=0,
            prefilter_ms=0,
            index=index,
        )

    # Check for bypass flag
    if os.environ.get(ENV_NO_PREFILTER) == "1":
        file_candidates = {str(p): set(index.rules.keys()) for p in files}
        return PrefilterResult(
            files_considered=total_files,
            files_after_prefilter=total_files,
            prefilter_ms=0,
            file_candidate_rules=file_candidates,
            ast_files=list(files),
            is_bypass=True,
            index=index,
        )

    t0 = time.perf_counter()

    if not index.expanded_rules:
        index.finalize()

    # If no literals exist, fall back to all files
    if not index.all_literals:
        file_candidates = {str(p): set(index.fallback_rules) for p in files}
        return PrefilterResult(
            files_considered=total_files,
            files_after_prefilter=total_files,
            prefilter_ms=0,
            file_candidate_rules=file_candidates,
            ast_files=list(files) if index.has_ast_fallback else [],
            is_bypass=False,
            index=index,
        )

    import tempfile
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="ubs_prefilter_lits_", delete=False) as tf:
        tf.write("\n".join(index.all_literals) + "\n")
        lits_file = tf.name

    file_matched_rules: dict[str, set[str]] = {}
    for p in files:
        fset = set(index.fallback_rules)
        file_matched_rules[str(p)] = fset
        try:
            file_matched_rules[str(p.resolve())] = fset
        except Exception:
            pass

    try:
        # Run ripgrep in chunks over the file list to avoid command line length limits
        file_strs = [str(p) for p in files]
        for start in range(0, len(file_strs), _RG_BATCH):
            batch = file_strs[start : start + _RG_BATCH]
            cmd = ["rg", "--json", "-i", "-F", "-f", lits_file, "--", *batch]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            except (subprocess.TimeoutExpired, OSError) as exc:
                sys.stderr.write(f"[ubs_core.prefilter] rg failed ({exc}); bypassing prefilter\n")
                return PrefilterResult(
                    files_considered=total_files,
                    files_after_prefilter=total_files,
                    prefilter_ms=0,
                    file_candidate_rules={str(p): set(index.rules.keys()) for p in files},
                    ast_files=list(files),
                    is_bypass=True,
                    index=index,
                )

            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if obj.get("type") == "match":
                    data = obj.get("data", {})
                    path_str = data.get("path", {}).get("text", "")
                    submatches = data.get("submatches", [])
                    if not path_str or not submatches:
                        continue
                    file_set = file_matched_rules.setdefault(path_str, set(index.fallback_rules))
                    try:
                        resolved_str = str(Path(path_str).resolve())
                        if resolved_str != path_str:
                            res_set = file_matched_rules.setdefault(resolved_str, file_set)
                            if res_set is not file_set:
                                file_set.update(res_set)
                                file_matched_rules[resolved_str] = file_set
                    except Exception:
                        pass
                    for sub in submatches:
                        matched_text = sub.get("match", {}).get("text", "").lower()
                        rules_for_lit = index.expanded_rules.get(matched_text) or index.literal_to_rules.get(matched_text)
                        if rules_for_lit:
                            file_set.update(rules_for_lit)
    finally:
        try:
            os.remove(lits_file)
        except OSError:
            pass

    t1 = time.perf_counter()
    prefilter_ms = max(1, int((t1 - t0) * 1000))

    # Compute candidate files and ast_files
    ast_files: list[Path] = []
    files_with_candidates = 0

    for p in files:
        p_str = str(p)
        cands = file_matched_rules.get(p_str, set())
        has_non_fallback = bool(cands - index.fallback_rules)
        if has_non_fallback:
            files_with_candidates += 1

        if index.has_ast_fallback or bool(cands & index.ast_rule_ids):
            ast_files.append(p)

    return PrefilterResult(
        files_considered=total_files,
        files_after_prefilter=files_with_candidates if files_with_candidates > 0 else (total_files if index.fallback_rules else 0),
        prefilter_ms=prefilter_ms,
        file_candidate_rules=file_matched_rules,
        ast_files=ast_files,
        is_bypass=False,
        index=index,
    )
