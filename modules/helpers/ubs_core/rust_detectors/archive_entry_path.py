"""ubs_core.rust_detectors.archive_entry_path — category 8 security (bead 0xjg.7).

Flags `.join()`/`.push()` destinations built from archive entry names.
Bindings follow lexical blocks, shadowing and function boundaries. Proven
collection pushes and filesystem directory entries are not extraction sinks;
unresolved archive-like receivers remain reviewable. An enclosed_name/canonicalize/
starts_with/strip_prefix/components/Component::Normal/unpack_in mention in the
surrounding window suppresses the hit. `ubs:ignore` on the flagged line
suppresses a hit.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterator
from pathlib import Path

from ubs_core.io import find_block_end
from ubs_core.lexer import strip_comments_and_strings
from ubs_core.suppression import has_suppression_marker

RULE_ID = "rust.security.archive-entry-path"
CATEGORY = 8
TITLE = "Archive entry path traversal risk"
SEVERITY = "warning"
DESCRIPTION = (
    "Use zip::read::ZipFile::enclosed_name(), tar::Entry::unpack_in(), or "
    "canonicalize and verify destination containment before writing"
)

# Documentation only: the orchestrator already passes the filtered file list
# (legacy rglob fallback applied this skip list).
skip_dirs = {".git", "target", ".cargo", "node_modules"}
archive_receiver = re.compile(r"(?:entry|file|member|archive|zip|tar)", re.IGNORECASE)
destination_call = re.compile(
    r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r"\s*\.\s*(?P<method>join|push)\s*\(",
    re.MULTILINE,
)
declaration = re.compile(
    r"\b(?:let|const|static)\s+(?:(?:mut|ref)\s+)*"
    r"(?:(?:Ok|Some)\s*\(\s*(?:mut\s+)?(?P<wrapped>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
    r"|(?P<pattern>\([^;=]+\)|[A-Za-z_][A-Za-z0-9_:]*\s*(?:\([^;=]+\)|\{[^;=]+\}))"
    r"|(?P<name>[A-Za-z_][A-Za-z0-9_]*))"
    r"\s*(?::(?!:)(?P<type>[^=;{}]+))?=(?![=>])\s*"
)
reassignment = re.compile(r"(?<![A-Za-z0-9_:.])(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=(?![=>])\s*")
accessor = re.compile(r"\b(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:name|path)\s*\(")
reference = re.compile(r"\s*&?\s*(?:mut\s+)?(?P<src>[A-Za-z_][A-Za-z0-9_]*)\b")
safe_context = re.compile(
    r"\b(?:enclosed_name|canonicalize|starts_with|strip_prefix|components\s*\(|Component::Normal|unpack_in)\b"
)


def expression_end(masked, start):
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


def type_kind(annotation):
    # Only the receiver's outer type can establish collection safety. A
    # Destination<Vec<u8>> may implement push by appending to a filesystem path.
    annotation = annotation.strip()
    annotation = re.sub(r"^(?:&\s*(?:'[A-Za-z_][A-Za-z0-9_]*\s+)?(?:mut\s+)?)+", "", annotation)
    if re.match(r"(?:(?:::)?(?:std|alloc)::vec::)?Vec\s*<", annotation):
        return "collection"
    if re.fullmatch(r"(?:::)?(?:std::)?fs::DirEntry", annotation):
        return "directory_entry"
    if re.match(r"(?:(?:::)?zip::read::)?ZipFile\b|(?:::)?tar::Entry\b", annotation):
        return "archive_entry"
    return None


def directory_iterator(expr, visible):
    """Recognize only adapters that preserve filesystem-entry provenance."""
    start = re.match(r"(?:std::)?fs::read_dir\s*\(", expr)
    if start:
        offset = find_block_end(expr, start.end() - 1, "(", ")") + 1
    else:
        source = reference.match(expr)
        if not source or visible.get(source.group("src")) != "directory_iterator":
            return False
        offset = source.end()
    preserving = {
        "unwrap", "expect", "flatten", "filter", "take", "skip", "take_while",
        "skip_while", "rev", "fuse", "peekable", "by_ref", "into_iter", "inspect",
    }
    while expr[offset:].strip():
        suffix = expr[offset:].lstrip()
        offset = len(expr) - len(suffix)
        if suffix.startswith("?"):
            offset += 1
            continue
        method = re.match(r"\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", suffix)
        if not method or method.group(1) not in preserving:
            return False
        opening = offset + method.end() - 1
        offset = find_block_end(expr, opening, "(", ")") + 1
    return True


def value_kind(expr, visible):
    expr = expr.strip()
    collection = re.match(r"(?:std::vec::)?Vec\s*(?:::<[^;]+>)?\s*::\s*(?:new|with_capacity)\s*\(|vec!\s*\[", expr)
    if collection:
        opening = collection.end() - 1
        closing = find_block_end(expr, opening, expr[opening], "]" if expr[opening] == "[" else ")")
        if not expr[closing + 1:].strip():
            return "collection"
    if directory_iterator(expr, visible):
        return "directory_iterator"
    if re.match(r"[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:by_index|by_name)\s*\(", expr):
        return "archive_entry"
    member = accessor.match(expr.lstrip("& \t\r\n"))
    if member:
        name = member.group("src")
        if visible.get(name) == "directory_entry":
            return None
        if visible.get(name) == "archive_entry" or archive_receiver.search(name):
            return "archive_path"
    alias = re.fullmatch(
        r"&?\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)"
        r"(?:\s*\.\s*(?:clone|to_owned|to_path_buf|as_ref|as_mut)\s*\(\s*\))*\s*\??", expr
    )
    if alias:
        return visible.get(alias.group(1))
    # Unknown expressions may select or transform a tainted value. A literal
    # replacement clears it, but an if/match expression is not a sanitizer.
    if any(visible.get(name) == "archive_path" for name in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr)):
        return "archive_path"
    for member in accessor.finditer(expr):
        name = member.group("src")
        if visible.get(name) != "directory_entry" and (visible.get(name) == "archive_entry" or archive_receiver.search(name)):
            return "archive_path"
    return None


def pattern_bindings(pattern):
    """Unknown pattern bindings shadow outer safety classifications."""
    # Match guards reference existing bindings; they do not redeclare them.
    # Keeping a captured archive alias visible here is essential to reporting
    # a destination even when the arm checks that its name is nonempty.
    pattern = re.split(r"\bif\b", pattern, maxsplit=1)[0]
    return {
        name: None for name in re.findall(r"\b[a-z_][A-Za-z0-9_]*\b", pattern)
        if name not in {"mut", "ref", "if", "true", "false", "self"}
    }


def closure_bindings(parameters):
    bindings = {}
    for parameter in parameters.split(","):
        pattern, _, annotation = parameter.partition(":")
        names = pattern_bindings(pattern)
        if len(names) == 1:
            names[next(iter(names))] = type_kind(annotation)
        bindings.update(names)
    return bindings


def closure_expression_end(masked, start):
    stack = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    for pos in range(start, len(masked)):
        char = masked[pos]
        if char in pairs:
            stack.append(pairs[char])
        elif stack and char == stack[-1]:
            stack.pop()
        elif not stack and char in ",;)]}":
            return pos
    return len(masked)


def arm_pattern(header):
    """Take the final arm pattern, keeping commas inside tuple patterns."""
    depth = 0
    for offset in range(len(header) - 1, -1, -1):
        char = header[offset]
        if char in ")]":
            depth += 1
        elif char in "([":
            depth -= 1
        elif char == "," and depth == 0:
            return header[offset + 1:]
    return header


def visible_bindings(scopes):
    visible = {}
    for bindings, boundary in reversed(scopes):
        for name, kind in bindings.items():
            visible.setdefault(name, kind)
        if boundary:
            break
    return visible


def function_bodies(masked):
    bodies = {}
    for item in re.finditer(r"\bfn\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^{};]*>)?\s*\(", masked):
        closing = find_block_end(masked, item.end() - 1, "(", ")")
        opening = masked.find("{", closing + 1)
        terminator = masked.find(";", closing + 1)
        if opening >= 0 and (terminator < 0 or opening < terminator):
            bodies[opening] = masked[item.end():closing]
    return bodies


def surrounding_code(lines, line_index):
    start = max(0, line_index - 8)
    end = min(len(lines), line_index + 4)
    return "\n".join(lines[start:end])


def find(files) -> Iterator[tuple[Path, int, int, str]]:
    """Yield (path, line, col, code), keeping direct hits before alias hits."""
    seen = set()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        masked = strip_comments_and_strings(text, lang="rust")
        original_lines = text.splitlines()
        masked_lines = masked.splitlines()
        starts = [0] + [match.end() for match in re.finditer("\n", text)]
        bodies = function_bodies(masked)
        scopes = [({}, True)]
        events = [(match.start(), "brace", match) for match in re.finditer(r"[{}]", masked)]
        declarations = list(declaration.finditer(masked))
        declaration_starts = [item.start() for item in declarations]
        for item in declarations:
            if not re.search(r"\b(?:if|while)\s*$", masked[max(0, item.start() - 32):item.start()]):
                events.append((expression_end(masked, item.end()), "declaration", item))
        for item in reassignment.finditer(masked):
            prior = bisect_right(declaration_starts, item.start()) - 1
            if prior < 0 or item.start() >= declarations[prior].end():
                events.append((expression_end(masked, item.end()), "assignment", item))
        for item in re.finditer(r"(?:^|[=(,:;{])\s*(?:(?:async|move)\s+)*\|([^|;\n]*)\|\s*", masked):
            if item.end() < len(masked) and masked[item.end()] != "{":
                events.append((item.end(), "binding_open", closure_bindings(item.group(1))))
                events.append((closure_expression_end(masked, item.end()), "closure_close", None))
        # Searching for the arrow first avoids ambiguous whitespace matching
        # over large masked string literals in files that have no arm here.
        for item in re.finditer(r"=>", masked):
            opening = item.end()
            while opening < len(masked) and masked[opening].isspace():
                opening += 1
            if opening < len(masked) and masked[opening] != "{":
                previous = max(masked.rfind(";", 0, item.start()), masked.rfind("{", 0, item.start()), masked.rfind("}", 0, item.start()))
                pattern = arm_pattern(masked[previous + 1:item.start()])
                events.append((opening, "binding_open", pattern_bindings(pattern)))
                events.append((closure_expression_end(masked, opening), "closure_close", None))
        events.extend((item.start(), "sink", item) for item in destination_call.finditer(masked))
        hits = []
        priority = {"closure_close": 0, "brace": 1, "binding_open": 2, "declaration": 3, "assignment": 3, "sink": 4}
        for offset, kind, event in sorted(events, key=lambda item: (item[0], priority[item[1]])):
            visible = visible_bindings(scopes)
            if kind == "binding_open":
                scopes.append((event, False))
                continue
            if kind == "closure_close":
                scopes.pop()
                continue
            if kind == "brace":
                if event.group() == "}":
                    if len(scopes) > 1:
                        scopes.pop()
                    continue
                bindings = {}
                boundary = offset in bodies
                if boundary:
                    for parameter in bodies[offset].split(","):
                        name = re.match(r"\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:(.*)", parameter)
                        if name:
                            bindings[name.group(1)] = type_kind(name.group(2))
                else:
                    previous = max(masked.rfind(";", 0, offset), masked.rfind("{", 0, offset), masked.rfind("}", 0, offset))
                    header = masked[previous + 1:offset]
                    loop = re.search(r"\bfor\s+(.+?)\s+in\s+(.+)$", header, re.DOTALL)
                    if loop:
                        iterator = loop.group(2).strip()
                        bindings.update(pattern_bindings(loop.group(1)))
                        single = re.fullmatch(r"(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)", loop.group(1).strip())
                        if single and directory_iterator(iterator, visible):
                            bindings[single.group(1)] = "directory_entry"
                    conditional = re.search(r"\b(?:if|while)\s+let\s+(.+?)\s*=(?!=)", header, re.DOTALL)
                    if conditional:
                        bindings.update(pattern_bindings(conditional.group(1)))
                    pattern, arrow, suffix = header.rpartition("=>")
                    if arrow and not suffix.strip():
                        bindings.update(pattern_bindings(arm_pattern(pattern)))
                    closure = re.search(r"\|([^|]*)\|\s*(?:->[^{}]+)?$", header)
                    if closure:
                        bindings.update(closure_bindings(closure.group(1)))
                scopes.append((bindings, boundary))
                continue
            if kind in ("declaration", "assignment"):
                name = event.group("name")
                annotation = ""
                if kind == "declaration":
                    if event.group("pattern"):
                        scopes[-1][0].update(pattern_bindings(event.group("pattern")))
                        continue
                    name = name or event.group("wrapped")
                    annotation = event.group("type") or ""
                expression = masked[event.end():offset]
                if kind == "declaration" and event.group("wrapped"):
                    expression = re.split(r"\belse\s*\{", expression, maxsplit=1)[0].rstrip()
                value = type_kind(annotation) or value_kind(expression, visible)
                target = scopes[-1][0]
                if kind == "assignment":
                    for bindings, boundary in reversed(scopes):
                        if name in bindings:
                            target = bindings
                            break
                        if boundary:
                            break
                    # A conditional assignment cannot establish an outer
                    # collection's safety or erase possible archive provenance.
                    if target is not scopes[-1][0] and value != target.get(name):
                        value = "archive_path" if "archive_path" in (value, target.get(name)) else None
                target[name] = value
                continue
            if event.group("method") == "push" and visible.get(event.group("dst")) == "collection":
                continue
            closing = find_block_end(masked, event.end() - 1, "(", ")")
            argument = masked[event.end():closing]
            member = accessor.match(argument.lstrip("& \t\r\n"))
            if member:
                archive_path = value_kind(argument, visible) == "archive_path"
            else:
                argument_ref = reference.match(argument)
                archive_path = argument_ref and visible.get(argument_ref.group("src")) == "archive_path"
            if not archive_path:
                continue
            line = bisect_right(starts, offset)
            context = surrounding_code(masked_lines, line - 1)
            if safe_context.search(context):
                continue
            code = original_lines[line - 1].strip() if 0 < line <= len(original_lines) else ""
            if has_suppression_marker(code, RULE_ID):
                continue
            key = (str(path), line, code)
            if key in seen:
                continue
            seen.add(key)
            hits.append((0 if member else 1, line, code))
        for _, line, code in sorted(hits):
            yield (path, line, 1, code)


if __name__ == "__main__":
    import sys

    root_files = [Path(p) for p in sys.argv[1:]]
    for path, line, col, code in find(root_files):
        print(f"{path}:{line}:{code}")
