"""ubs_core.prefilter — Necessary-literal prefilter for ast-grep, patterns, and analyzers (bead C2).

Extracts necessary literal tokens from structured ast-grep rules and regex
syntax trees. One ripgrep pass computes per-file candidates. Checks without
a proven source requirement, including arbitrary analyzer callbacks, remain
eligible for every selected file.

Conservative by construction: rules with no extractable literal fall back to
matching all files. UBS_NO_PREFILTER=1 disables prefiltering entirely.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

# Environment variable to disable prefiltering for A/B testing
ENV_NO_PREFILTER = "UBS_NO_PREFILTER"

# Batch size for ripgrep file argument lists (ARG_MAX safety)
_RG_BATCH = 400

# Known rules that need full coverage. Other unprovable expressions also use
# explicit fallback; this table is NOT permission to guess source requirements.
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
    literal_pattern: re.Pattern[str] | None = None

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
        self.expanded_rules.clear()
        self.literal_pattern = None

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
        # ripgrep reports non-overlapping submatches. Look ahead at every
        # position in each matched line so one literal cannot hide another
        # (e.g. abcd and cdef in abcdef). Longest-first plus containment
        # expansion covers shorter matches that start at the same position.
        self.literal_pattern = re.compile(
            "(?=(" + "|".join(re.escape(lit) for lit in self.all_literals) + "))",
            re.IGNORECASE | re.ASCII,
        ) if self.all_literals else None


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


def _pattern_identifier_literals(pattern: str) -> set[str]:
    """Extract fixed identifiers without mistaking metavariable names for code."""
    cleaned = re.sub(r"[$]+[A-Za-z0-9_]*", " ", pattern)
    return {word for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cleaned)
            if len(word) >= 2 and word.lower() not in ("true", "false")}


def _structured_rule_literals(rule: Any, depth: int = 0) -> set[str]:
    """Return a conservative OR-set of literals from required JSON constraints.

    Scalar code patterns and simple identifier regexes are interpreted.
    Pattern contexts, negated rules, and stopBy traversal boundaries are not
    matched source and must never contribute prefilter requirements.
    """
    if not isinstance(rule, dict) or depth > 48:
        return set()

    literals: set[str] = set()
    pattern = rule.get("pattern")
    if isinstance(pattern, str) and not re.search(r'''["'`#\\]|//|/\*''', pattern):
        # Scalar patterns use smart matching: fixed identifiers must occur,
        # while metavariables can match arbitrary nodes (including no nodes).
        # Do not require punctuation or dotted adjacency, which can vary in
        # otherwise matching source. Quoted/comment/escaped forms stay on the
        # fallback path rather than guessing which text belongs to the AST.
        literals.update(_pattern_identifier_literals(pattern))
    regex = rule.get("regex")
    if isinstance(regex, str):
        match = re.fullmatch(r"(?:\\b)?([A-Za-z_][A-Za-z0-9_]*)(?:\\b)?", regex)
        if match:
            literals.add(match.group(1))

    for relation in ("has", "inside", "precedes", "follows"):
        literals.update(_structured_rule_literals(rule.get(relation), depth + 1))

    conjunction = rule.get("all")
    if isinstance(conjunction, list):
        for member in conjunction:
            literals.update(_structured_rule_literals(member, depth + 1))

    alternatives = rule.get("any")
    if isinstance(alternatives, list) and alternatives:
        branches = [_structured_rule_literals(member, depth + 1) for member in alternatives]
        if all(branches):
            # At least one branch must match. A branch without a proven
            # literal makes this disjunction unsuitable for prefiltering.
            for branch in branches:
                literals.update(branch)
    return literals


def extract_ast_rule_literals(rule_id: str, rule_text: str | dict, lang: str = "") -> set[str]:
    """Extract necessary literal strings from an ast-grep rule definition.

    A literal is necessary if ANY match of this rule must contain it in source code.
    If the rule has multiple branches (any:), the rule requires at least one of
    the branch literals. If no necessary literal can be extracted, returns an empty set.
    """
    # Whitelisted rules that have no keyword literals
    if rule_id in ALLOWED_EMPTY_RULES.get(lang, set()):
        return set()

    if isinstance(rule_text, dict):
        return _structured_rule_literals(rule_text.get("rule", rule_text))

    text = str(rule_text)
    if re.match(r'\s*\{\s*(?:"|\})', text):
        try:
            document = json.loads(text)
        except ValueError:
            return set()
        if not isinstance(document, dict):
            return set()
        return _structured_rule_literals(document.get("rule", document))

    # YAML formatting, alternatives, pattern contexts and metadata cannot be
    # understood by grepping for words. Use the same structural proof as JSON.
    # PyYAML is optional: without it this optimization simply admits all files,
    # rather than making it a new scanner runtime dependency.
    try:
        import yaml
    except ImportError:
        return set()
    try:
        documents = list(yaml.safe_load_all(text))
        branches = [
            _structured_rule_literals(doc.get("rule", doc)) if isinstance(doc, dict) else set()
            for doc in documents
        ]
    except (yaml.YAMLError, ValueError, RecursionError):
        return set()
    return set().union(*branches) if branches and all(branches) else set()


def _extract_regex_literals(regex: Any) -> set[str]:
    """Prove an OR-set of necessary literals from Python's regex syntax tree.

    A concatenation may use any mandatory child; an alternation needs a proof
    for EVERY branch. Optional repeats, negative assertions, group names and
    verbose comments are never source requirements. Unknown syntax or a
    runtime without CPython's parser disables this optimization safely.
    """
    if not regex:
        return set()
    pat = regex.pattern if hasattr(regex, "pattern") else str(regex)
    if not isinstance(pat, str):
        return set()

    def alternatives(branches) -> set[str]:
        proofs = [walk(branch) for branch in branches]
        return set().union(*proofs) if proofs and all(proofs) else set()

    def walk(sequence) -> set[str]:
        literals: set[str] = set()
        run: list[str] = []

        def flush() -> None:
            literals.update(re.findall(r"[a-z_][a-z0-9_]{1,}", "".join(run)))
            run.clear()

        for opcode, value in sequence:
            op = str(opcode)
            if op == "LITERAL":
                run.append(chr(value).lower())
                continue
            if op == "IN" and all(str(kind) == "LITERAL" for kind, _ in value):
                chars = {chr(code).lower() for _, code in value}
                if len(chars) == 1:
                    run.append(chars.pop())
                    continue
            flush()
            if op == "SUBPATTERN":
                literals.update(walk(value[-1]))
            elif op in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                if value[0] > 0:
                    literals.update(walk(value[2]))
            elif op == "BRANCH":
                literals.update(alternatives(value[1]))
            elif op == "ASSERT":
                literals.update(walk(value[1]))
            elif op == "ATOMIC_GROUP":
                literals.update(walk(value))
            elif op == "GROUPREF_EXISTS":
                literals.update(alternatives((value[1], value[2] or [])))
            elif op not in ("IN", "AT", "ANY", "NOT_LITERAL", "CATEGORY", "ASSERT_NOT", "GROUPREF"):
                return set()
        flush()
        return literals

    try:
        from re import _parser
        return walk(_parser.parse(pat, getattr(regex, "flags", 0)))
    except (ImportError, AttributeError, ValueError, TypeError, OverflowError, RecursionError, re.error):
        return set()


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
            # An arbitrary callback's name is not a necessary source predicate.
            # Global guessed keyword lists omitted real sinks (e.g. writeFile,
            # unlink, mkdir and sendFile in the path-traversal analyzer). Let
            # callbacks apply their own guards to the complete selection.
            index.add_rule(RuleSpec(
                rule_id=aname,
                literals=frozenset(),
                is_fallback=True,
                kind="analyzer",
            ))

    index.finalize()
    return index


def _rg_bytes(value: Any) -> bytes:
    """Decode ripgrep's lossless text-or-base64 JSON data representation."""
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError("expected a text/bytes data object")
    if "text" in value and isinstance(value["text"], str):
        return value["text"].encode("utf-8")
    if "bytes" in value and isinstance(value["bytes"], str):
        return base64.b64decode(value["bytes"], validate=True)
    raise ValueError("invalid text/bytes data object")


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

    def bypass(reason: str) -> PrefilterResult:
        # An optimizer failure is not evidence that a source file is clean.
        # Run every selected check normally, leaving scanner error reporting
        # (including inaccessible inputs) to the actual analysis layers.
        sys.stderr.write(f"[ubs_core.prefilter] {reason}; bypassing prefilter\n")
        return PrefilterResult(
            files_considered=total_files, files_after_prefilter=total_files,
            prefilter_ms=max(1, int((time.perf_counter() - t0) * 1000)),
            ast_files=list(files), is_bypass=True, index=index,
        )

    if any(not p.is_file() for p in files):
        return bypass("selection contains a missing or nonregular file")

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

    file_matched_rules: dict[str, set[str]] = {}
    for p in files:
        try:
            fset = file_matched_rules.setdefault(str(p.resolve()), set(index.fallback_rules))
            file_matched_rules[str(p)] = fset
        except OSError as exc:
            return bypass(f"cannot resolve selected input ({exc})")

    import tempfile
    from ubs_core.external_tools import run_command

    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="ubs_prefilter_lits_") as tf:
            if any(not lit or any(c in lit for c in "\r\n\0") for lit in index.all_literals):
                return bypass("literal cannot be represented in a line-oriented search")
            tf.write("\n".join(re.escape(lit) for lit in index.all_literals) + "\n")
            # Native scanners differ in Unicode folding and invalid UTF-8 repair
            # (ignore vs replace). Any non-ASCII byte therefore admits ALL checks
            # for that file; it cannot be used as negative prefilter evidence.
            tf.write(r"(?-u:[\x80-\xff])" + "\n")
            tf.flush()
            # Run ripgrep in chunks to avoid command line length limits.
            # Absolute operands prevent a file named '-' from becoming stdin.
            file_strs = [str(p.absolute()) for p in files]
            for start in range(0, len(file_strs), _RG_BATCH):
                batch = file_strs[start : start + _RG_BATCH]
                cmd = ["rg", "--no-config", "--json", "--text", "-i", "-f", tf.name, "--", *batch]
                errors: list[str] = []
                proc = run_command("prefilter rg", cmd, Path.cwd(), 60, errors)
                if proc is None or errors:
                    return bypass("; ".join(errors) or "rg produced no result")
                if proc.returncode not in (0, 1):
                    return bypass(f"rg exited {proc.returncode}")

                active: set[str] = set()
                summary_seen = False
                matches = 0
                for line in proc.stdout.splitlines():
                    if not line.strip():
                        continue
                    obj = json.loads(line)
                    if not isinstance(obj, dict) or not isinstance(obj.get("data"), dict) or summary_seen:
                        raise ValueError("invalid rg JSON event")
                    kind, data = obj.get("type"), obj["data"]
                    if kind == "summary":
                        stats = data.get("stats")
                        if (active or not isinstance(stats, dict)
                                or type(stats.get("matches")) is not int
                                or stats["matches"] != matches):
                            raise ValueError("incomplete rg summary")
                        summary_seen = True
                        continue
                    path_str = os.fsdecode(_rg_bytes(data.get("path")))
                    resolved = str(Path(path_str).resolve())
                    if not path_str or "\0" in path_str or resolved not in file_matched_rules:
                        raise ValueError("rg returned an unselected path")
                    file_set = file_matched_rules[resolved]
                    if kind == "begin" and resolved not in active:
                        active.add(resolved)
                    elif kind == "end" and resolved in active:
                        if data.get("binary_offset") is not None:
                            raise ValueError("rg stopped early on binary content")
                        active.remove(resolved)
                    elif kind == "match" and resolved in active:
                        source = _rg_bytes(data.get("lines"))
                        submatches = data.get("submatches")
                        if not isinstance(submatches, list) or not submatches:
                            raise ValueError("missing rg submatches")
                        for sub in submatches:
                            if (not isinstance(sub, dict) or type(sub.get("start")) is not int
                                    or type(sub.get("end")) is not int
                                    or not 0 <= sub["start"] < sub["end"] <= len(source)
                                    or _rg_bytes(sub.get("match")) != source[sub["start"]:sub["end"]]):
                                raise ValueError("invalid rg submatch")
                        matches += len(submatches)
                        if not source.isascii():
                            file_set.update(index.rules)
                        elif index.literal_pattern is not None:
                            for match in index.literal_pattern.finditer(source.decode("ascii")):
                                file_set.update(index.expanded_rules[match.group(1).lower()])
                    else:
                        raise ValueError("unexpected rg event order or type")
                if not summary_seen or bool(matches) != (proc.returncode == 0):
                    raise ValueError("missing or inconsistent rg completion summary")
    except (OSError, ValueError, RecursionError) as exc:
        return bypass(f"invalid or incomplete rg result ({exc})")

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
