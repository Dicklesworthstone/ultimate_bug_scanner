"""Bounded native Python HTTP/TLS configuration and request identities.

Requests sessions accept per-request verify; aiohttp sessions accept ssl.
HTTPX configures verification on clients/transports, not client request
methods. Reuse the timeout detector's lexical native-call visitor for
imports, captured methods, argument evaluation, branches and scopes,
while supplying a separate TLS policy. A response or a similar spelling
never acquires a native client's authority.

This is an explicit configuration check. It does not prove the complete
TLS policy of an arbitrary helper, subclass or externally configured object.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.py_detectors.http_timeout import HttpTimeoutAnalyzer, UNKNOWN, _Value
from ubs_core.suppression import SourceSuppressions

RULE_ID = "py.security.tls-verification"
CATEGORY = 7
TITLE = "HTTP/TLS client disables certificate verification"
SEVERITY = "critical"
DESCRIPTION = "Keep certificate and hostname verification enabled; use explicit CA bundles for private trust roots"

REQUEST_METHODS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "request",
})
CLIENT_CONSTRUCTORS = {
    "requests.Session": "requests",
    "requests.session": "requests",
    "requests.sessions.Session": "requests",
    "httpx.Client": "httpx",
    "httpx.AsyncClient": "httpx",
    "aiohttp.ClientSession": "aiohttp",
    "urllib3.PoolManager": "urllib3",
    "urllib3.ProxyManager": "urllib3",
    "ssl.SSLContext": "ssl_context",
    "ssl.create_default_context": "ssl_context",
    "ssl._create_unverified_context": "ssl_context",
    "aiohttp.TCPConnector": "aiohttp_connector",
    "httpx.HTTPTransport": "httpx_transport",
    "httpx.AsyncHTTPTransport": "httpx_transport",
}
CLIENT_METHODS = {
    "requests": REQUEST_METHODS | {"send"},
    "aiohttp": REQUEST_METHODS | {"ws_connect"},
}


def _literal_false(values) -> bool:
    # Strings such as "false" and "off" can name CA bundles. They are not
    # Boolean False and must not borrow a different library's coercion.
    return any(value.kind == "literal" and value.data is False for value in values)


def _ssl_hostname_disabled(values) -> bool:
    # SSLContext.check_hostname applies Python truthiness to its argument.
    # Unlike HTTPX/aiohttp options, zero, None and empty literals disable it,
    # while nonempty strings such as "false" leave verification enabled.
    return any(value.kind == "literal" and not value.data for value in values)


def _requests_verify_disabled(values, *, none_disables=False) -> bool:
    # Request/get inherit the session default for None. Session.send passes
    # an explicit None through to the adapter, and setting Session.verify
    # stores None as the default itself; both disable certificate checks.
    return any(value.kind == "literal"
               and (none_disables if value.data is None else not value.data)
               for value in values)


def _cert_none(values, *, string_names=False) -> bool:
    for value in values:
        if value.kind == "native" and value.name == "ssl.CERT_NONE":
            return True
        if value.kind == "literal":
            if isinstance(value.data, int) and value.data == 0:
                return True
            if string_names and value.data in ("CERT_NONE", "NONE"):
                return True
    return False


class _TLSVerificationAnalyzer(HttpTimeoutAnalyzer):
    """Share native binding state; do not execute the timeout policy."""

    def remember_issue(self, line_no):
        if self.suppression.is_suppressed(line_no, RULE_ID) or line_no in self.seen_lines:
            return
        self.seen_lines.add(line_no)
        self.issues.append(line_no)

    def values(self, node):
        if isinstance(node, ast.Constant):
            # False and 0 compare/hash equally in Python, but HTTPX and
            # aiohttp accept Boolean False and reject numeric substitutes.
            # Keep that distinction when abstract alternatives are joined.
            return frozenset({_Value("literal", type(node.value).__name__, node.value)})
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            result = set()
            for value in self.values(node.operand):
                if value.kind == "literal" and isinstance(value.data, (int, float)):
                    number = -value.data if isinstance(node.op, ast.USub) else +value.data
                    result.add(_Value("literal", type(number).__name__, number))
                else:
                    result.update(UNKNOWN)
            return frozenset(result) or UNKNOWN
        if isinstance(node, ast.Attribute):
            result = set()
            for owner in self.values(node.value):
                if owner.kind == "native":
                    key = f"{owner.name}.{node.attr}"
                    result.update(self.member_overrides.get(key, frozenset({_Value("native", key)})))
                elif owner.kind == "client" and node.attr in CLIENT_METHODS.get(owner.name, ()):
                    key = (owner, node.attr)
                    result.update(self.member_overrides.get(key, self.member_default(key)))
                else:
                    result.update(UNKNOWN)
            return frozenset(result) or UNKNOWN
        return super().values(node)

    def keyword_values(self, call, name):
        # Use the value captured when this argument was evaluated. A later
        # keyword may rebind the same name. Opaque **kwargs grant no policy
        # proof; this bounded check retains explicit keyword semantics.
        for keyword in call.keywords:
            if keyword.arg == name:
                return self.argument_values(call, keyword.value)
        return UNKNOWN

    def call_result(self, node, callees):
        results = set()
        for callee in callees:
            if callee.kind == "method":
                owner = callee.data
                if owner.name == "requests" and callee.name in CLIENT_METHODS["requests"]:
                    if _requests_verify_disabled(self.keyword_values(node, "verify"),
                                                 none_disables=callee.name == "send"):
                        self.remember_issue(node.lineno)
                elif owner.name == "aiohttp" and callee.name in CLIENT_METHODS["aiohttp"]:
                    if (_literal_false(self.keyword_values(node, "ssl"))
                            or _literal_false(self.keyword_values(node, "verify_ssl"))):
                        self.remember_issue(node.lineno)
                results.update(UNKNOWN)
                continue

            name = callee.name if callee.kind == "native" else ""
            family = CLIENT_CONSTRUCTORS.get(name)
            if family:
                results.add(self.native_client(node, family))
                if family in {"httpx", "httpx_transport"}:
                    if _literal_false(self.keyword_values(node, "verify")):
                        self.remember_issue(node.lineno)
                elif family == "aiohttp_connector":
                    if (_literal_false(self.keyword_values(node, "ssl"))
                            or _literal_false(self.keyword_values(node, "verify_ssl"))):
                        self.remember_issue(node.lineno)
                elif family == "urllib3":
                    if (_cert_none(self.keyword_values(node, "cert_reqs"), string_names=True)
                            or _literal_false(self.keyword_values(node, "assert_hostname"))):
                        self.remember_issue(node.lineno)
                elif name == "ssl._create_unverified_context":
                    self.remember_issue(node.lineno)
                continue

            module, _, method = name.rpartition(".")
            if module in {"requests", "requests.api"} and method in REQUEST_METHODS:
                if _requests_verify_disabled(self.keyword_values(node, "verify")):
                    self.remember_issue(node.lineno)
            elif module == "httpx" and method in REQUEST_METHODS | {"stream"}:
                if _literal_false(self.keyword_values(node, "verify")):
                    self.remember_issue(node.lineno)
            elif name == "aiohttp.request":
                if (_literal_false(self.keyword_values(node, "ssl"))
                        or _literal_false(self.keyword_values(node, "verify_ssl"))):
                    self.remember_issue(node.lineno)
            results.update(UNKNOWN)
        return frozenset(results) or UNKNOWN

    def bind(self, target, values):
        if isinstance(target, ast.Attribute):
            owners = self.values(target.value)
            for owner in owners:
                if owner.kind == "client":
                    if (owner.name == "requests" and target.attr == "verify"
                            and _requests_verify_disabled(values, none_disables=True)):
                        self.remember_issue(target.lineno)
                    elif owner.name == "ssl_context":
                        if (target.attr == "verify_mode" and _cert_none(values)
                                or target.attr == "check_hostname" and _ssl_hostname_disabled(values)):
                            self.remember_issue(target.lineno)
                    if target.attr in CLIENT_METHODS.get(owner.name, ()):
                        key = (owner, target.attr)
                        previous = self.member_overrides.get(key, self.member_default(key))
                        self.member_overrides[key] = values if len(owners) == 1 else previous | values
                elif owner.kind == "native" and owner.name == "ssl" and target.attr == "_create_default_https_context":
                    if any(value.kind == "native" and value.name == "ssl._create_unverified_context"
                           for value in values):
                        self.remember_issue(target.lineno)
        super().bind(target, values)

    def visit_ListComp(self, node):
        # Python evaluates only the first iterable in the enclosing class
        # namespace. The implicit comprehension function resolves its body
        # and later iterables through the class's enclosing scope instead.
        outer, enclosing = self.snapshot(), self.class_enclosing
        self.visit(node.generators[0].iter)
        if enclosing is not None:
            self.restore(enclosing)
        self.class_enclosing = None
        # Every comprehension target is local throughout its implicit
        # function, including before a later generator binds it. Prebind
        # them after evaluating the first iterable in the enclosing scope.
        for generator in node.generators:
            self.bind(generator.target, UNKNOWN)
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
            self.bind(generator.target, UNKNOWN)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.restore(outer)
        self.class_enclosing = enclosing

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_While(self, node):
        if isinstance(node.test, ast.Constant) and not node.test.value:
            self.visit(node.test)
            for statement in node.orelse:
                self.visit(statement)
            return
        super().visit_While(node)

    def visit_Lambda(self, node):
        # The shared visitor masks positional/keyword-only parameters. TLS
        # also masks *args/**kwargs before inspecting a lambda body so a
        # captured client cannot lend identity to an unrelated parameter.
        for expression in (*node.args.defaults,
                           *(value for value in node.args.kw_defaults if value is not None)):
            self.visit(expression)
        outer, enclosing = self.snapshot(), self.class_enclosing
        if enclosing is not None:
            self.restore(enclosing)
        self.class_enclosing = None
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                         *((node.args.vararg,) if node.args.vararg else ()),
                         *((node.args.kwarg,) if node.args.kwarg else ())):
            self.bindings[argument.arg] = UNKNOWN
        self.visit(node.body)
        self.restore(outer)
        self.class_enclosing = enclosing


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    suppressions = SourceSuppressions("python")
    for path in files:
        if path.suffix.lower() not in {".py", ".pyi"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        analyzer = _TLSVerificationAnalyzer(lines, suppressions.index(path, text))
        analyzer.visit(tree)
        for line_no in analyzer.issues:
            code = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            yield path, line_no, 1, code[:240]
