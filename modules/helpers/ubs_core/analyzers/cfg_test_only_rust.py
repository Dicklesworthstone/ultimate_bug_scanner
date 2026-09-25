"""ubs_core.analyzers.cfg_test_only_rust — resolve #[cfg(test)]-only modules (bead A2).

The modules/helpers/cfg_test_only_modules_rust.py script is a thin entrypoint.
Part of the fix for GH #80: `--exclude-tests`
must also exclude files that are test-only because every `mod name;`
declaration referencing them is gated by `#[cfg(test)]` (directly or
transitively via another test-only file). A file that is also referenced by at
least one non-test `mod` declaration stays included.

Input:  --files-from FILE  (newline-delimited paths of the authoritative scan
        set; only paths from this set are ever reported)
Output: one path per line (spelled exactly as in the input list) for every
        file that is test-only.

Also exposes a structured `run(ctx)` for the `python3 -m ubs_core` CLI.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ubs_core.lexer import strip_comments_and_strings
from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.rust_scan import is_test_attr

# Both inline and out-of-line modules, including raw identifiers and visibility.
MOD_DECL_RE = re.compile(
    r"(?:pub\s*(?:\([^)]*\)\s*)?)?mod\s+([^\s;{}]+)\s*([;{])"
)
ATTR_OPEN_RE = re.compile(r"#\s*(!\s*)?\[")
PATH_KEY_RE = re.compile(r"\b(?:r#)?path\s*=\s*")
INCLUDE_RE = re.compile(r"(?:r#)?include\s*!\s*([({\[])")
TOKEN_RE = re.compile(r"(?:r#)?\w+|\S")
CRATE_ROOT_NAMES = {"lib.rs", "main.rs", "mod.rs"}
_MAX_PATH_VARIANTS = 32
_MAX_SCOPE_DEPTH = 256


def _delimited_end(masked: str, start: int) -> int | None:
    """Find a complete attribute token tree without interpreting literal text."""
    closers = {"[": "]", "(": ")", "{": "}"}
    stack = [closers[masked[start]]]
    for pos in range(start + 1, len(masked)):
        ch = masked[pos]
        if ch in closers:
            stack.append(closers[ch])
            if len(stack) > _MAX_SCOPE_DEPTH:
                return None
        elif ch in "])}":
            if ch != stack.pop():
                return None
            if not stack:
                return pos + 1
    return None


def _path_literal(text: str, start: int) -> tuple[str, int] | None:
    """Read ordinary/raw path literals; unsupported escapes keep all files scanned."""
    while start < len(text) and text[start].isspace():
        start += 1
    raw = re.match(r'r(#{0,255})"', text[start:])
    if raw:
        value_start = start + raw.end()
        end = text.find('"' + raw.group(1), value_start)
        if end >= 0:
            return text[value_start:end], end + 1 + len(raw.group(1))
        return None
    if start >= len(text) or text[start] != '"':
        return None
    try:
        value, consumed = json.JSONDecoder().raw_decode(text[start:])
    except ValueError:
        return None
    return (value, start + consumed) if isinstance(value, str) else None


def _attribute_paths(attrs: list[str]) -> tuple[list[str], bool] | None:
    """Collect every possible path, retaining the default for conditional paths.

    Unknown cfg_attr predicates may select a production alias, so each literal
    path participates in the reference graph. No target configuration is guessed.
    """
    paths: list[str] = []
    has_direct_path = False
    for attr in attrs:
        clean = strip_comments_and_strings(attr, lang="rust", strip_strings=False)
        masked = strip_comments_and_strings(attr, lang="rust")
        direct = re.match(r"\s*(?:r#)?path\s*=", clean)
        conditional = re.match(r"\s*(?:r#)?cfg_attr\s*\(", clean)
        if not direct and not conditional:
            continue
        for key in PATH_KEY_RE.finditer(masked):
            # Whitespace masking includes the literal itself; locate its start
            # from the '=' instead of the end of the greedy whitespace match.
            literal = _path_literal(clean, masked.index("=", key.start()) + 1)
            if literal is None:
                return None
            value, end = literal
            if direct and clean[end:].strip():
                return None
            paths.append(value)
        has_direct_path = has_direct_path or bool(direct)
    return paths, not has_direct_path


def _cfg_gated(attr: str) -> bool:
    clean = strip_comments_and_strings(attr, lang="rust", strip_strings=False)
    return bool(re.match(r"\s*(?:r#)?cfg\s*\(", clean)) and is_test_attr("#[" + attr + "]")


@dataclass
class _Scope:
    module_dirs: tuple[Path, ...]
    path_dirs: tuple[Path, ...]
    closer: str = ""
    gated: bool = False
    trusted: bool = True
    inner_allowed: bool = True


def _module_references(declaring: Path, text: str, *, as_crate_root: bool = False) -> list[tuple[Path, bool]] | None:
    """Read lexical module references, failing conservatively on ambiguous scopes.

    Only file/inline-module bodies authorize exclusions. References in other
    token trees (including macro bodies) can keep files visible but cannot grant
    test-only authority. Comments and literals never contribute declarations.
    """
    masked = strip_comments_and_strings(text, lang="rust")
    base = declaring.parent
    module_base = base if as_crate_root or declaring.name in CRATE_ROOT_NAMES else base / declaring.stem
    scopes = [_Scope((module_base,), (base,))]
    refs: list[tuple[Path, bool]] = []
    attrs: list[str] = []
    pos = 0
    while pos < len(masked):
        if masked[pos].isspace():
            pos += 1
            continue
        scope = scopes[-1]
        attr_open = ATTR_OPEN_RE.match(masked, pos)
        if attr_open:
            end = _delimited_end(masked, attr_open.end() - 1)
            if end is None:
                return None
            attr = text[attr_open.end():end - 1]
            if attr_open.group(1):
                if scope.inner_allowed and scope.trusted:
                    scope.gated = scope.gated or _cfg_gated(attr)
            else:
                attrs.append(attr)
            pos = end
            continue

        scope.inner_allowed = False
        module = MOD_DECL_RE.match(masked, pos)
        if module:
            paths = _attribute_paths(attrs)
            if paths is None:
                return None
            path_values, include_default = paths
            name = module.group(1).removeprefix("r#")
            if not name.isidentifier():
                return None
            gated = scope.trusted and (scope.gated or any(_cfg_gated(attr) for attr in attrs))
            explicit = [directory / path for directory in scope.path_dirs for path in path_values]
            defaults = [directory / name for directory in scope.module_dirs] if include_default else []
            if len(explicit) + len(defaults) > _MAX_PATH_VARIANTS:
                return None
            if module.group(2) == ";":
                targets = explicit + [candidate for directory in defaults
                                      for candidate in (directory.with_suffix(".rs"), directory / "mod.rs")]
                refs.extend((target, gated) for target in targets)
            else:
                directories = tuple(dict.fromkeys(explicit + defaults))
                scopes.append(_Scope(directories, directories, "}", gated, scope.trusted))
                if len(scopes) > _MAX_SCOPE_DEPTH:
                    return None
            attrs = []
            pos = module.end()
            continue

        attrs = []
        include = INCLUDE_RE.match(masked, pos)
        if include:
            end = _delimited_end(masked, include.end() - 1)
            if end is None:
                return None
            arguments = strip_comments_and_strings(text[include.end():end - 1], lang="rust", strip_strings=False)
            literal = _path_literal(arguments, 0)
            if literal is None or arguments[literal[1]:].strip() not in ("", ","):
                # A computed include path may name any scanned file.
                return None
            # include! paths are relative to the source file, even in inline
            # modules. Preserve these possible production uses conservatively.
            refs.append((declaring.parent / literal[0], False))
            pos = end
            continue
        ch = masked[pos]
        if ch in "{([":
            scopes.append(_Scope(scope.module_dirs, scope.path_dirs,
                                 {"{": "}", "(": ")", "[": "]"}[ch], trusted=False))
            if len(scopes) > _MAX_SCOPE_DEPTH:
                return None
        elif ch in "})]":
            if len(scopes) == 1 or scopes[-1].closer != ch:
                return None
            scopes.pop()
        token = TOKEN_RE.match(masked, pos)
        pos = token.end() if token else pos + 1
    return refs if len(scopes) == 1 else None


def compute_test_only(raw_entries: list[str]) -> list[str]:
    """Return the test-only subset of a scan set, spelled as given and sorted.

    Only paths from the authoritative scan set are ever reported; unreferenced
    files are never test-only.
    """
    entries = [e for e in raw_entries if e.strip() and e.endswith(".rs")]
    by_resolved: dict[Path, str] = {}
    for entry in entries:
        try:
            by_resolved[Path(entry).resolve()] = entry
        except OSError:
            continue

    # target(resolved) -> list of (source_resolved, cfg_test_gated).
    # None is a production-preserving edge from an uncertain crate-root view;
    # it cannot inherit test-only authority from another module context.
    refs: dict[Path, list[tuple[Path | None, bool]]] = {}
    source_refs: dict[Path, list[tuple[Path, bool]]] = {}

    for resolved, entry in by_resolved.items():
        try:
            text = Path(entry).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            # An unreadable source might contain a production reference.
            return []
        references = _module_references(resolved, text)
        if references is None:
            return []
        source_refs[resolved] = []
        for target, gated in references:
            try:
                tr = target.resolve()
            except OSError:
                return []
            if tr in by_resolved:
                source_refs[resolved].append((tr, gated))

        if resolved.name not in CRATE_ROOT_NAMES:
            # Cargo bin/example/custom target roots need not be called main.rs
            # or lib.rs. Without target metadata, also retain files reachable
            # from their root interpretation; guessed paths never exclude files.
            root_references = _module_references(resolved, text, as_crate_root=True)
            if root_references is None:
                return []
            for target, gated in root_references:
                if gated:
                    continue
                try:
                    tr = target.resolve()
                except OSError:
                    return []
                if tr in by_resolved:
                    refs.setdefault(tr, []).append((None, False))

    # A non-root filename has a reliable ordinary-module interpretation only
    # when reached through declarations from a recognized source root. An
    # unreferenced custom root cannot exclude guessed stem/name.rs siblings.
    known_sources = {path for path in by_resolved if path.name in CRATE_ROOT_NAMES}
    pending = list(known_sources)
    while pending:
        source = pending.pop()
        for target, _ in source_refs.get(source, ()):
            if target not in known_sources:
                known_sources.add(target)
                pending.append(target)
    for source, targets in source_refs.items():
        for target, gated in targets:
            refs.setdefault(target, []).append((source, gated and source in known_sources))

    # Fixpoint: test-only if every reference is cfg(test)-gated or comes from
    # a file that is itself test-only. Unreferenced files are never test-only.
    test_only: set[Path] = set()
    changed = True
    while changed:
        changed = False
        for target, sources in refs.items():
            if target in test_only or not sources:
                continue
            if all(gated or src in test_only for src, gated in sources):
                test_only.add(target)
                changed = True

    return [by_resolved[r] for r in sorted(test_only, key=lambda p: by_resolved[p])]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--files-from", required=True)
    args = ap.parse_args()

    try:
        raw_entries = Path(args.files_from).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(f"cannot read file list: {exc}", file=sys.stderr)
        return 1

    for entry in compute_test_only(raw_entries):
        print(entry)
    return 0


_MESSAGE = "file is reachable only through #[cfg(test)]-gated `mod` declarations"


def run(ctx: RunContext) -> Iterable[dict]:
    for entry in compute_test_only([str(p) for p in ctx.files]):
        yield {
            "rule": "rust.prefilter.test_only_module",
            "path": entry,
            "line": 1,
            "layer": "prefilter",
            "lang": "rust",
            "severity": "info",
            "message": _MESSAGE,
        }


def _write_fixture(src: Path, lib_text: str) -> list[Path]:
    src.mkdir(parents=True, exist_ok=True)
    (src / "lib.rs").write_text(lib_text, encoding="utf-8")
    (src / "tests_support.rs").write_text(
        "pub fn helper_value() -> u32 {\n    let missing: Option<u32> = None;\n    missing.unwrap()\n}\n",
        encoding="utf-8",
    )
    return [src / "lib.rs", src / "tests_support.rs"]


def _selftest_cfg_gated_only() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_cfg_test_only_rust_") as tmp:
        files = _write_fixture(
            Path(tmp) / "src", "#[cfg(test)]\nmod tests_support;\n"
        )
        result = compute_test_only([str(p) for p in files])
    assert result == [str(files[1])], result


def _selftest_nongated_ref_keeps_file() -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ubs_core_cfg_test_only_rust_") as tmp:
        files = _write_fixture(Path(tmp) / "src", "mod tests_support;\n")
        result = compute_test_only([str(p) for p in files])
    assert result == [], result


def _selftest_run(tmp_prefix: str = "ubs_core_cfg_test_only_rust_run_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        files = _write_fixture(
            Path(tmp) / "src", "#[cfg(test)]\nmod tests_support;\n"
        )
        findings = list(run(RunContext(lang="rust", files=files)))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "rust.prefilter.test_only_module"
    assert findings[0]["path"] == str(files[1])
    assert findings[0]["severity"] == "info"


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("cfg_gated_only_is_test_only", _selftest_cfg_gated_only),
    ("nongated_ref_keeps_file", _selftest_nongated_ref_keeps_file),
    ("run_reports_test_only", _selftest_run),
)

register(Analyzer(layer="prefilter", lang="rust", name="cfg_test_only_rust", run=run, selftests=SELF_TESTS))
