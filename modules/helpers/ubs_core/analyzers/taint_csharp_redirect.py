"""C# request-to-redirect dataflow using the shared C# CFG and summaries (D6).

Local-url predicates refine only the branch on which validation succeeds.
Local helpers are analyzed by their bodies, including returns and ref/out
effects. File-path sanitizers and promising helper names do not validate URLs.
URI allowlists require the parsed URI, an absolute HTTPS scheme and exact,
constant hosts in the same guard. Only the selected source file is inspected;
heap, virtual-dispatch and cross-file summaries remain outside this frontend.
"""
from __future__ import annotations

from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.analyzers.taint_csharp_request import CSharpFlow, parts
from ubs_core.suppression import SourceSuppressions
from ubs_core.taint_flow import CLEAN, advance, join
import re
import sys
from pathlib import Path

RULE = "csharp.taint.open_redirect"
MESSAGE = "Unvalidated redirect from request data"
LOCAL_VALIDATORS = frozenset({"Url.IsLocalUrl", "this.Url.IsLocalUrl",
                            "RedirectHttpResult.IsLocalUrl",
                            "Microsoft.AspNetCore.Http.HttpResults.RedirectHttpResult.IsLocalUrl"})


class RedirectFlow(CSharpFlow):
    rule = RULE
    message = MESSAGE
    request_members = r"\.(?:Request\.)?(?:Query|Form|RouteValues|Headers|Cookies|Host|Path|PathBase|RawTarget|QueryString)\b"
    source_pattern = re.compile(
        r"\b(?:Request|request|req)\s*\.\s*(?:Query|Form|RouteValues|Headers|Cookies|Host|Path|PathBase|RawTarget|QueryString)\b")

    def canonical(self, name):
        name = re.sub(r"\s|@", "", name).replace("global::", "")
        root = name.split(".")[0]
        if root in self.aliases:
            name = self.aliases[root] + name[len(root):]
        return name

    def literal(self, start, end):
        """Read only literal values at syntax-validated argument positions."""
        value = self.text[start:end].strip()
        if re.fullmatch(r'"[^"\\]*"', value):
            return value[1:-1]
        if re.fullmatch(r'@"(?:[^"\n]|"")*"', value):
            return value[2:-1].replace('""', '"')
        return None

    def strip_parentheses(self, start, end):
        while True:
            while start < end and self.text[start].isspace():
                start += 1
            while end > start and self.text[end - 1].isspace():
                end -= 1
            if self.code[start:start + 1] == "(" and self.parser.pairs.get(start) == end - 1:
                start, end = start + 1, end - 1
            else:
                return start, end

    def path_guard(self, span, bindings=None):
        bindings = bindings or {}
        start, end = self.strip_parentheses(*span)
        truth = True
        if self.code[start:start + 1] == "!":
            truth = False
            low, high = self.strip_parentheses(start + 1, end)
        else:
            low, high = start, end
        match = re.fullmatch(r"([\w.@:]+)\s*\(\s*(@?\w+)\s*\)", self.code[low:high])
        if match:
            name, variable = match.groups()
            canonical = self.canonical(name)
            if (canonical in LOCAL_VALIDATORS and name.split(".")[0] not in bindings
                    and not self.resolve(name, 1)):
                return variable.lstrip("@"), "local-url", truth
        return self.uri_guard(start, end, bindings)

    def uri_guard(self, start, end, bindings):
        """A rejecting OR guard proves its negated branch's parsed URI safe.

        The original string is deliberately retained: parsing can normalize a
        URI, and a check of one object must not validate another string/object.
        """
        segments = list(parts(self.code, start, end, separator="|"))
        # Splitting || produces an empty middle piece. Reject |, mixed &&,
        # expressions with side effects, and unrecognized extra disjuncts.
        if len(segments) != 5 or self.code[slice(*segments[1])].strip() or self.code[slice(*segments[3])].strip():
            return None
        parsed, scheme, host = (self.strip_parentheses(*segments[index]) for index in (0, 2, 4))
        match = re.fullmatch(
            r"!\s*((?:System\.)?Uri)\.TryCreate\s*\(\s*(@?\w+)\s*,\s*(?:System\.)?UriKind\.Absolute\s*,\s*out\s+(?:(?:var|(?:System\.)?Uri)\s+)?(@?\w+)\s*\)",
            self.code[slice(*parsed)])
        if (not match or self.canonical(match.group(1)) not in {"Uri", "System.Uri"}
                or match.group(1).split(".")[0] in bindings or self.resolve(match.group(1) + ".TryCreate", 3)):
            return None
        uri = match.group(3).lstrip("@")
        expected = rf"\s*{re.escape(uri)}\s*\.\s*Scheme\s*!=\s*(?:System\.)?Uri\.UriSchemeHttps\s*"
        if not re.fullmatch(expected, self.code[slice(*scheme)]):
            return None
        host_code = self.code[slice(*host)]
        equal = re.fullmatch(rf"\s*{re.escape(uri)}\.Host\s*!=\s*(.+)\s*", host_code)
        if equal:
            value = self.literal(host[0] + equal.start(1), host[0] + equal.end(1))
            if value and re.fullmatch(r"[A-Za-z0-9.-]+", value):
                return uri, "absolute-host", False
        membership = re.fullmatch(rf"\s*!\s*([\w.]+)\.Contains\s*\(\s*{re.escape(uri)}\.Host\s*\)\s*", host_code)
        if membership and self.constant_hosts(membership.group(1), bindings):
            return uri, "absolute-host", False
        return None

    def constant_hosts(self, name, bindings):
        """Recognize a private literal host set that never escapes or mutates.

        A readonly reference alone is insufficient: every use in the selected
        source must be the exact Host-membership predicate. The name of a set
        conveys no trust, and ambiguous declarations fail conservatively.
        """
        if "." in name or name in bindings:
            return False
        for typename, builtin in (("HashSet", "System.Collections.Generic.HashSet"),
                                  ("StringComparer", "System.StringComparer")):
            if typename in self.aliases and self.aliases[typename] != builtin:
                return False
            if any(owner.rsplit(".", 1)[-1] == typename for _, _, owner in self.parser.types):
                return False
        escaped = re.escape(name)
        declarations = list(re.finditer(
            rf"\bprivate\s+static\s+readonly\s+(?:System\.Collections\.Generic\.)?HashSet\s*<\s*string\s*>\s+{escaped}\s*=\s*new\s*(?:(?:System\.Collections\.Generic\.)?HashSet\s*<\s*string\s*>)?\s*\(\s*(?:StringComparer\.OrdinalIgnoreCase\s*)?\)\s*\{{", self.code))
        if len(declarations) != 1:
            return False
        declaration = declarations[0]
        opening = declaration.end() - 1
        closing = self.parser.pairs[opening]
        entries = list(parts(self.code, opening + 1, closing))
        hosts = [self.literal(low, high) for low, high in entries]
        if not hosts or any(not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host) for host in hosts):
            return False
        owners = tuple(owner for low, high, owner in self.parser.types if low < declaration.start() < high)
        if owners != self.function.owner:
            return False
        for use in re.finditer(rf"\b{escaped}\b", self.code):
            if declaration.start() <= use.start() <= closing:
                continue
            # Includes declarations, assignment, Add/Remove/Clear, passing the
            # reference to helpers, and aliases to a mutable set.
            if not re.match(r"\.Contains\s*\(\s*\w+\.Host\s*\)", self.code[use.end():]):
                return False
        return True

    def apply_guard(self, action, state):
        cell = action.bindings.get(action.guard[0])
        if cell:
            state.pop(cell, None)
        return state

    def external_value(self, name, values, receiver):
        if name in LOCAL_VALIDATORS or name in {"Uri.TryCreate", "System.Uri.TryCreate"}:
            return CLEAN
        # Path.GetFileName, HTML escaping, URL encoding and arbitrary Safe*
        # helpers do not establish a safe redirect destination.
        return join(receiver, *values)

    def sink_arguments(self, name, args):
        name = name.removeprefix("<instance>.")
        owner, _, method = name.rpartition(".")
        response = owner == "Response" or owner.endswith(".Response")
        redirect = re.fullmatch(r"Redirect(?:Permanent|PreserveMethod|PermanentPreserveMethod)?", method)
        if redirect and (response or owner in {"", "this", "Results", "TypedResults", "Microsoft.AspNetCore.Http.Results", "Microsoft.AspNetCore.Http.TypedResults"}):
            keywords = {"url", "location"} if response else {"url"}
        elif method == "RedirectResult" and owner in {"", "Microsoft.AspNetCore.Mvc"}:
            keywords = {"url"}
        elif method in {"Add", "Append"} and (owner == "Response.Headers" or owner.endswith(".Response.Headers")):
            headers = [index for index, (key, _, _) in enumerate(args) if (key is None and index == 0) or key == "key"]
            key = self.literal(*args[headers[0]][1:]) if headers else None
            if key is None or key.casefold() != "location":
                return []
            return [index for index, (key, _, _) in enumerate(args) if (key is None and index == 1) or key == "value"]
        else:
            return []
        return [index for index, (key, _, _) in enumerate(args) if (key is None and index == 0) or key in keywords]

    def transfer(self, action, state):
        start, end = action.span
        if action.kind in {"simple", "eval"}:
            # Location header writes are sinks, not assignments to the whole
            # HttpContext receiver. Inspect only the RHS of the actual setter.
            match = re.match(r"\s*((?:\w+\.)*Response\.Headers)\s*(\[|\.Location\b)", self.code[start:end])
            if match:
                stop = start + match.end()
                header = match.group(2) == ".Location"
                if match.group(2) == "[":
                    close = self.parser.pairs[stop - 1]
                    key = self.literal(stop, close)
                    header = key is not None and key.casefold() == "location"
                    stop = close + 1
                assignment = re.match(r"\s*=(?!=|>)", self.code[stop:end])
                if header and assignment:
                    value = self.evaluate(stop + assignment.end(), end, state, action.bindings)
                    if value:
                        name = match.group(1) + ".Location"
                        key = (start + match.start(1), name)
                        value = advance(value, self.step(key[0], "sink", name))
                        self.effects[key] = join(self.effects.get(key, CLEAN), value)
                    return state
        return super().transfer(action, state)


def analyze(path: Path, issues):
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    for finding in run(RunContext(lang="csharp", files=[path])):
        trace = " -> ".join(step["label"] for step in finding["extras"]["taint_path"])
        issues.append((str(path), finding["line"], f"{lines[finding['line'] - 1].strip()}  [{trace}]"))


def main(argv: list[str] | None = None) -> int:
    """Reproduce the module heredoc: `python3 - <project_dir> <nul-filelist> <<PY` emit dialect."""
    argv = sys.argv if argv is None else list(argv)
    if len(argv) < 3:
        raise ValueError("Expected project directory and NUL-separated file list")
    paths = [Path(raw.decode("utf-8", "surrogateescape")) for raw in Path(argv[2]).read_bytes().split(b"\0") if raw]
    issues = []
    for file_path in paths:
        analyze(file_path, issues)
    for file_name, line_no, code in issues:
        print(f"{file_name}:{line_no}:{code}")
    return 0


def run(ctx: RunContext) -> Iterable[dict]:
    if not ctx.rule_enabled(RULE):
        return
    suppressions = SourceSuppressions("csharp")
    for path in ctx.files:
        if path.suffix.lower() not in {".cs", ".csx"}:
            continue
        text = path.read_text(encoding="utf-8-sig")
        if not re.search(r"\b(?:Request|request|req|HttpRequest|HttpRequestBase|HttpContext)\b", text):
            continue
        for finding in RedirectFlow(path, text).analyze():
            if not suppressions.is_suppressed(path, finding["line"], RULE):
                yield finding


def _selftest_direct_source_to_sink() -> None:
    import tempfile

    code = (
        "var url = Request.Query[\"returnUrl\"];\n"
        "Response.Redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_csharp_redirect_") as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "csharp.taint.open_redirect"
    assert findings[0]["line"] == 2
    assert findings[0]["severity"] == "critical"


def _selftest_ubs_ignore_suppression() -> None:
    import tempfile

    code = (
        "var url = Request.Query[\"returnUrl\"];\n"
        "Response.Redirect(url);  // ubs:ignore\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_csharp_redirect_") as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert findings == [], findings


def _selftest_local_url_guard_suppression() -> None:
    import tempfile

    code = (
        "var url = Request.Query[\"returnUrl\"];\n"
        "if (!Url.IsLocalUrl(url)) { return BadRequest(); }\n"
        "Response.Redirect(url);\n"
    )
    with tempfile.TemporaryDirectory(prefix="ubs_core_taint_csharp_redirect_") as tmp:
        target = Path(tmp) / "A.cs"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="csharp", files=[target])))
    assert findings == [], findings


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_to_sink", _selftest_direct_source_to_sink),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("local_url_guard_suppression", _selftest_local_url_guard_suppression),
)

register(Analyzer(layer="taint", lang="csharp", name="taint_csharp_redirect", run=run, selftests=SELF_TESTS))
