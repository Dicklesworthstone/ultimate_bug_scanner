"""ubs_core.analyzers.ctcompare_py — Python timing-safe secret comparison analysis (bead A2).

Extracted verbatim from the ``run_constant_time_compare_checks`` heredoc in
modules/ubs-python.sh: an AST walk that flags ``==``/``!=`` comparisons
involving secret material (HMACs, API keys, CSRF tokens, reset tokens, ...)
where ``hmac.compare_digest()`` / ``secrets.compare_digest()`` should be used.

Two-tier vocabulary (GH #85): strong terms (secret, password, signature, ...)
are security-sensitive on their own unless the very next identifier term is
schema/metadata vocabulary (signature_format, credential_type, jwt_header).
Weak terms (token, key, digest, nonce, ...) are ordinary parser/domain
vocabulary and only become sensitive next to a security qualifier in the same
identifier (auth_token, api_key, session_token, webhook_signature).

Digest role (GH #102): ``.digest()``/``.hexdigest()`` is secret material when
the receiver is keyed (hmac.new(...), HMAC(...), blake2b(..., key=...)) or
hashes secret material (sha256(password)), and stays reported when the
receiver cannot be resolved in the function. An unkeyed hashlib digest of
non-secret bytes (``hashlib.sha256(payload).hexdigest()`` against a public
manifest checksum) is an integrity check, not an authentication tag, and is
not reported.

Signal role (GH #193): a function-local, single-assignment ``*_sig`` read
from a literal dictionary's ``signal``/``*_signal`` field can be a public
categorical label. Only literal enum-like strings, immutable scalar aliases,
and dictionaries with no writes or escapes establish that role. Unknown
signal data, conditional/repeated bindings, security-qualified names, and a
sensitive operand on either side of the comparison remain reported.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import build_index

ROOT: Path = Path.cwd()
BASE_DIR: Path = ROOT

SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
# GH #85 two-tier vocabulary (same sets as the Rust module). Strong terms are
# security-sensitive on their own unless the very next identifier term is
# schema/metadata vocabulary (signature_format, credential_type, jwt_header).
# Weak terms (token, key, digest, nonce, session, mac, ...) are ordinary
# parser/domain vocabulary and only become sensitive next to a security
# qualifier in the same identifier (auth_token, api_key, session_token,
# webhook_signature). Identifiers are split into terms first, so `TARGET_SIGS`
# no longer matches `sig` by substring and a bare parser `token == "rm"` is
# not reported as a secret comparison.
STRONG_TERMS = {
    'secret', 'password', 'passwd', 'pwd', 'bearer', 'hmac', 'csrf', 'xsrf',
    'otp', 'totp', 'mfa', 'signature', 'sig', 'credential', 'credentials',
    'authorization', 'jwt',
}
WEAK_TERMS = {
    'token', 'key', 'mac', 'digest', 'nonce', 'session', 'auth', 'reset',
    'webhook', 'invite', 'verification', 'recovery',
}
QUALIFIER_TERMS = {
    'api', 'auth', 'access', 'refresh', 'session', 'reset', 'recovery',
    'verification', 'invite', 'jwt', 'csrf', 'xsrf', 'webhook', 'hmac',
    'bearer', 'secret', 'signing', 'signature', 'private', 'otp', 'totp',
    'mfa', 'password', 'passwd', 'pwd', 'credential', 'credentials',
}
METADATA_TERMS = {
    'field', 'format', 'kind', 'layout', 'policy', 'schema', 'state',
    'status', 'type', 'mode', 'scheme', 'parser', 'alg', 'algorithm',
    'aud', 'audience', 'claim', 'claims', 'exp', 'expiration', 'header',
    'headers', 'issuer', 'iss', 'kid', 'name', 'label', 'id', 'index',
    'count', 'len', 'length', 'scope', 'scopes',
}

# `SIG_DFL`, `SIG_IGN`, `SIG_ERR`, `SIG_BLOCK`, ... are POSIX signal
# dispositions and mask operations (`previous == signal.SIG_DFL`), not
# signatures. Real signal numbers (`SIGTERM`) are one term and never match.
SIGNAL_DISPOSITION_TERMS = {'dfl', 'ign', 'err', 'hold', 'block', 'unblock', 'setmask'}
# A signature of code, not of data: `call_signature`, `function_sig`,
# `method_signature`, `type_signature`. The qualifier must directly precede
# the term, so `webhook_signature` and `request_sig` stay sensitive.
# `reference`/`ref` are deliberately absent: `reference_signature` is how
# verification code names the expected MAC.
CODE_SIGNATURE_TERMS = {'signature', 'sig'}
CODE_SIGNATURE_QUALIFIERS = {
    'call', 'function', 'func', 'fn', 'method', 'type', 'overload',
    'callable', 'parameter', 'param',
}

# Unkeyed hashlib constructors (GH #102). ``hashlib.new`` is unkeyed too but is
# only accepted with the explicit ``hashlib.`` owner, because a bare ``new`` may
# be ``from hmac import new``. blake2b/blake2s become keyed MACs with ``key=``.
UNKEYED_HASH_CTORS = {
    'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
    'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'shake_128', 'shake_256',
    'blake2b', 'blake2s',
}
KEYED_BLAKE_KWARGS = {'key'}

def identifier_terms(text):
    text = re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])', ' ', text)
    text = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', text)
    return re.findall(r'[a-z0-9]+', text.lower())

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in {'.py', '.pyi'}:
            yield root
        return
    for path in root.rglob('*'):
        if path.is_file() and path.suffix.lower() in {'.py', '.pyi'} and not should_skip(path):
            yield path

def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    return ''

def const_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''

RULE_ID = 'python.ctcompare.secret_eq'

def target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(target_names(elt))
        return names
    return []

def name_is_sensitive(name):
    if not name:
        return False
    terms = identifier_terms(name)
    for idx, term in enumerate(terms):
        if term in STRONG_TERMS:
            follower = terms[idx + 1] if idx + 1 < len(terms) else ''
            leader = terms[idx - 1] if idx > 0 else ''
            if term == 'sig' and follower in SIGNAL_DISPOSITION_TERMS:
                continue  # signal.SIG_DFL / SIG_IGN: a handler disposition
            if term in CODE_SIGNATURE_TERMS and leader in CODE_SIGNATURE_QUALIFIERS:
                continue  # call_signature / method_sig: a code-shape signature
            if follower not in METADATA_TERMS:
                return True
            continue
        if term in WEAK_TERMS and any(
            other_idx != idx and other in QUALIFIER_TERMS
            for other_idx, other in enumerate(terms)
        ):
            return True
    return False

def value_names_non_secret_vocabulary(value):
    """A call whose name uses secret vocabulary in a non-secret sense.

    `sig = self._call_signature(node)` binds a code signature: the callee's
    name carries a strong/weak term (`signature`) that its own qualifiers
    already classify as non-secret. The binding's abbreviated name (`sig`)
    adds nothing, so it inherits that classification instead of being judged
    on its own. A callee with no such vocabulary (`sig = compute(body)`) says
    nothing about the value, and the name alone still decides.
    """
    if not isinstance(value, ast.Call):
        return False
    name = call_name(value.func).rsplit('.', 1)[-1]
    terms = identifier_terms(name)
    vocabulary = any(term in STRONG_TERMS or term in WEAK_TERMS for term in terms)
    return vocabulary and not name_is_sensitive(name)


def public_signal_bindings(function):
    """Return assignment values with a proven local categorical signal role.

    This is a deliberately narrow must-proof, separate from the analyzer's
    existing branch traversal. Only direct statements in the function body
    qualify, and every binding of a candidate name is counted across the
    entire syntax tree, including branches and nested scopes. A second write,
    parameter, import, capture, global/nonlocal declaration, or deletion rules
    out that name even when it occurs after a comparison. Dictionaries must
    be literal, single-bound, and used only for literal-key get/subscript
    reads: aliases, mutation, and passing the dictionary to a call defeat the
    proof. Namespace/frame reflection also defeats it, including references
    later invoked through a local or import alias. No claim is made about
    arbitrary .get("signal") calls, globals,
    interprocedural values, or all possible public categorical expressions.
    """
    nodes = list(ast.walk(function))
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    writes = {}
    loads = {}
    excluded = set()
    security_terms = STRONG_TERMS | WEAK_TERMS | QUALIFIER_TERMS
    reflection_names = {
        'locals', 'globals', 'vars', 'eval', 'exec', '__builtins__', '__dict__',
        'getattr', '__getattribute__', 'currentframe', '_getframe',
        '_current_frames', 'f_locals', 'f_globals', 'getouterframes',
        'getinnerframes', 'stack', 'trace',
    }
    # Match captures arrived in 3.10 and type parameters in 3.12. The helper
    # still runs on 3.9, where those AST classes do not exist.
    named_bindings = tuple(
        getattr(ast, kind) for kind in (
            'MatchAs', 'MatchStar', 'TypeVar', 'ParamSpec', 'TypeVarTuple',
        ) if hasattr(ast, kind)
    )
    mapping_pattern = getattr(ast, 'MatchMapping', ())
    for node in nodes:
        reference = (
            node.id if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
            else node.attr if isinstance(node, ast.Attribute)
            else node.name.rsplit('.', 1)[-1] if isinstance(node, ast.alias)
            else None
        )
        if reference in reflection_names:
            return {}
        bound = []
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                loads.setdefault(node.id, []).append(node)
            else:
                bound.append(node.id)
        elif isinstance(node, ast.arg):
            bound.append(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.append(node.name)
        elif isinstance(node, ast.alias):
            bound.append(node.asname or node.name.split('.')[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.append(node.name)
        elif isinstance(node, named_bindings) and node.name:
            bound.append(node.name)
        elif isinstance(node, mapping_pattern) and node.rest:
            bound.append(node.rest)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            excluded.update(node.names)
        for name in bound:
            writes[name] = writes.get(name, 0) + 1

    def public_name(name, *, allow_sig=False):
        terms = identifier_terms(name)
        if allow_sig and terms and terms[-1] == 'sig':
            terms = terms[:-1]
        return not any(term in security_terms for term in terms)

    def public_label(value):
        text = const_string(value)
        return (
            text is not None
            and re.fullmatch(r'[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*', text) is not None
            and public_name(text)
        )

    def read_only_map(name):
        for load in loads.get(name, ()):
            parent = parents.get(load)
            if (
                isinstance(parent, ast.Subscript) and parent.value is load
                and isinstance(parent.ctx, ast.Load)
                and const_string(parent.slice) is not None
            ):
                continue
            call = parents.get(parent)
            if (
                isinstance(parent, ast.Attribute) and parent.value is load
                and parent.attr == 'get' and isinstance(call, ast.Call)
                and call.func is parent and len(call.args) in (1, 2)
                and not call.keywords and const_string(call.args[0]) is not None
            ):
                continue
            return False
        return True

    maps = {}
    public_values = set()
    bindings = {}
    for statement in function.body:
        if isinstance(statement, ast.Assign) and all(
            isinstance(target, ast.Name) for target in statement.targets
        ):
            names = [target.id for target in statement.targets]
            value = statement.value
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            names = [statement.target.id]
            value = statement.value
        else:
            continue
        eligible = {
            name for name in names
            if writes.get(name) == 1 and name not in excluded
            and public_name(name, allow_sig=True)
        }
        if not eligible or value is None:
            continue
        if isinstance(value, ast.Dict) and len(names) == 1 and read_only_map(names[0]):
            fields = {}
            for key, item in zip(value.keys, value.values):
                field = const_string(key)
                if field is None:
                    fields.clear()  # unpacking/dynamic keys may replace any field
                    break
                terms = identifier_terms(field)
                fields[field] = (
                    bool(terms) and terms[-1] == 'signal'
                    and public_name(field) and public_label(item)
                )  # the last literal occurrence wins for duplicate keys
            maps[names[0]] = {field for field, public in fields.items() if public}
            continue
        public = isinstance(value, ast.Name) and value.id in public_values
        receiver = key = None
        if isinstance(value, ast.Subscript):
            receiver, key = value.value, const_string(value.slice)
        elif (
            isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
            and value.func.attr == 'get' and len(value.args) in (1, 2)
            and not value.keywords
            and (
                len(value.args) == 1 or public_label(value.args[1])
                or isinstance(value.args[1], ast.Constant) and value.args[1].value is None
            )
        ):
            receiver, key = value.func.value, const_string(value.args[0])
        if isinstance(receiver, ast.Name) and key in maps.get(receiver.id, ()):
            public = True
        if public:
            bindings[value] = eligible
            public_values.update(eligible)
    return bindings


def is_constant_display(node):
    """A tuple/list/set display built only from literals: `("a", "b")`."""
    return isinstance(node, (ast.Tuple, ast.List, ast.Set)) and all(
        isinstance(elt, ast.Constant) for elt in node.elts
    )


class ConstantTimeCompareAnalyzer(ast.NodeVisitor):
    def __init__(self, path, lines, suppressions=None):
        self.path = path
        self.lines = lines
        # Shared comment-owned statement index (GH #153, #154): a marker on any
        # physical line of the comparison's statement (or a standalone marker
        # directly above it) suppresses it, but only a bare marker or one that
        # lists this rule id; marker text inside string literals never counts.
        self.suppressions = (
            suppressions if suppressions is not None
            else build_index('\n'.join(lines), lang='python')
        )
        self.sensitive_names = set()
        # Names bound to an unkeyed hashlib object fed only non-secret data
        # (GH #102): their .digest()/.hexdigest() is a checksum, not a tag.
        self.unkeyed_hash_names = set()
        # Names whose secret-looking spelling is explained by a non-secret
        # binding (`sig = self._call_signature(node)`).
        self.explained_names = set()
        self.public_signal_bindings = {}
        self.issues = []
        self.seen_lines = set()

    def relative_path(self):
        try:
            return str(self.path.relative_to(BASE_DIR))
        except ValueError:
            return self.path.name

    def remember_issue(self, line_no):
        if line_no in self.seen_lines or self.suppressions.is_suppressed(line_no, RULE_ID):
            return
        self.seen_lines.add(line_no)
        self.issues.append((self.relative_path(), line_no, source_line(self.lines, line_no)))

    def expr_is_sensitive(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.sensitive_names or (
                node.id not in self.explained_names and name_is_sensitive(node.id)
            )
        if isinstance(node, ast.Attribute):
            # Judge only the attribute being compared. Including the receiver
            # made ORM column comparisons like `Token.user_id == user_uuid`
            # look sensitive purely because of the model class name (#64).
            return name_is_sensitive(node.attr)
        if isinstance(node, ast.Subscript):
            key = const_string(node.slice)
            return name_is_sensitive(key or '') or self.expr_is_sensitive(node.value)
        if isinstance(node, ast.Call):
            name = call_name(node.func)
            short = name.rsplit('.', 1)[-1]
            owner = name.rsplit('.', 1)[0] if '.' in name else ''
            if name_is_sensitive(name) or name in {'hmac.new', 'hashlib.pbkdf2_hmac'} or owner == 'hmac':
                return True
            if short in {'digest', 'hexdigest'}:
                if isinstance(node.func, ast.Attribute):
                    return self.digest_is_sensitive(node.func.value)
                return True  # bare digest(...): provenance unknown, keep reporting
            return False
        if isinstance(node, ast.BinOp):
            return self.expr_is_sensitive(node.left) or self.expr_is_sensitive(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self.expr_is_sensitive(value) for value in node.values)
        return False

    def is_unkeyed_hash_ctor(self, call):
        """hashlib.sha256(...) / sha256(...) / hashlib.new(...) without a MAC key."""
        name = call_name(call.func)
        owner, _, short = name.rpartition('.')
        if owner not in ('', 'hashlib'):
            return False
        if short == 'new':
            return owner == 'hashlib'
        if short not in UNKEYED_HASH_CTORS:
            return False
        if short.startswith('blake2') and any(kw.arg in KEYED_BLAKE_KWARGS for kw in call.keywords):
            return False
        return True

    def call_input_is_sensitive(self, call):
        return any(self.expr_is_sensitive(arg) for arg in call.args) or any(
            self.expr_is_sensitive(kw.value) for kw in call.keywords
        )

    def digest_is_sensitive(self, receiver):
        """Role of a .digest()/.hexdigest() receiver (GH #102).

        A keyed or unknown constructor, a hash over secret material, and an
        unresolved receiver all stay secret material; only an unkeyed hashlib
        digest of non-secret data is a plain integrity checksum.
        """
        if isinstance(receiver, ast.Call):
            if self.is_unkeyed_hash_ctor(receiver):
                return self.call_input_is_sensitive(receiver)
            return True
        if isinstance(receiver, ast.Name):
            return receiver.id not in self.unkeyed_hash_names
        return True

    def mark_assignment(self, names, value):
        value_sensitive = self.expr_is_sensitive(value)
        explained = not value_sensitive and value_names_non_secret_vocabulary(value)
        public_signals = self.public_signal_bindings.get(value, ())
        unkeyed_hash = (
            isinstance(value, ast.Call)
            and self.is_unkeyed_hash_ctor(value)
            and not self.call_input_is_sensitive(value)
        )
        for name in names:
            name_explained = explained or (not value_sensitive and name in public_signals)
            if value_sensitive or (name_is_sensitive(name) and not name_explained):
                self.sensitive_names.add(name)
            else:
                self.sensitive_names.discard(name)
            if name_explained:
                self.explained_names.add(name)
            else:
                self.explained_names.discard(name)
            if unkeyed_hash and not name_is_sensitive(name):
                self.unkeyed_hash_names.add(name)
            else:
                self.unkeyed_hash_names.discard(name)

    def visit_FunctionDef(self, node):
        old_sensitive = set(self.sensitive_names)
        old_unkeyed = set(self.unkeyed_hash_names)
        old_explained = set(self.explained_names)
        old_public_signals = self.public_signal_bindings
        self.sensitive_names.clear()
        self.unkeyed_hash_names.clear()
        self.explained_names.clear()
        self.public_signal_bindings = public_signal_bindings(node)
        for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
            if name_is_sensitive(arg.arg):
                self.sensitive_names.add(arg.arg)
        if node.args.vararg and name_is_sensitive(node.args.vararg.arg):
            self.sensitive_names.add(node.args.vararg.arg)
        if node.args.kwarg and name_is_sensitive(node.args.kwarg.arg):
            self.sensitive_names.add(node.args.kwarg.arg)
        for stmt in node.body:
            self.visit(stmt)
        self.sensitive_names = old_sensitive
        self.unkeyed_hash_names = old_unkeyed
        self.explained_names = old_explained
        self.public_signal_bindings = old_public_signals

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        names = [name for target in node.targets for name in target_names(target)]
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            names = target_names(node.target)
            if names:
                self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_Call(self, node):
        # h = hashlib.sha256(); h.update(secret)  -> h is no longer a plain checksum.
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == 'update'
            and isinstance(func.value, ast.Name)
            and func.value.id in self.unkeyed_hash_names
            and self.call_input_is_sensitive(node)
        ):
            self.unkeyed_hash_names.discard(func.value.id)
        self.generic_visit(node)

    def visit_Compare(self, node):
        if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            values = [node.left] + list(node.comparators)
            # Comparing against a number, boolean, or None (e.g.
            # `total_tokens == 0`) can never leak secret material through
            # timing; only string/bytes comparisons are timing-sensitive (#64).
            # A literal tuple/list/set (`sig == ("socket", "socketpair")`) is
            # a structured key, never a secret string or bytes value; the
            # comparison is a shape dispatch, not a credential check.
            non_secret_literal = any(
                isinstance(value, ast.Constant) and not isinstance(value.value, (str, bytes))
                or is_constant_display(value)
                for value in values
            )
            if not non_secret_literal and any(self.expr_is_sensitive(value) for value in values):
                self.remember_issue(node.lineno)
        self.generic_visit(node)

def analyze(path, issues):
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(text, filename=str(path))
    except Exception:
        return
    lines = text.splitlines()
    analyzer = ConstantTimeCompareAnalyzer(path, lines, build_index(text, lang='python'))
    analyzer.visit(tree)
    issues.extend(analyzer.issues)


def main(argv: list[str] | None = None) -> int:
    """CLI driver: same stdout as the extracted heredoc for the same argv."""
    global ROOT, BASE_DIR
    args = list(sys.argv if argv is None else argv)
    if len(args) < 2:
        print('usage: ctcompare_py <project_dir>', file=sys.stderr)
        return 2
    ROOT = Path(args[1]).resolve()
    BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
    issues = []
    for file_path in iter_files(ROOT):
        analyze(file_path, issues)
    print(f'__COUNT__\t{len(issues)}')
    for file_name, line_no, code in issues[:25]:
        print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
    return 0


_SEVERITY = "critical"
_MESSAGE = (
    "Secret, signature, or token compared with ==/!=; "
    "use hmac.compare_digest() or secrets.compare_digest()"
)


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        issues: list[tuple[str, int, str]] = []
        analyze(path, issues)
        for _file, line_no, _code in issues:
            display = str(path)
            if path.is_absolute():
                try:
                    display = str(path.relative_to(cwd))
                except ValueError:
                    display = str(path)
            yield {
                "rule": RULE_ID,
                "path": display,
                "line": line_no,
                "col": 1,
                "layer": "ctcompare",
                "lang": "python",
                "severity": _SEVERITY,
                "message": _MESSAGE,
            }


def _scan_code(code: str) -> list[tuple[str, int, str]]:
    lines = code.splitlines()
    visitor = ConstantTimeCompareAnalyzer(Path("memory.py"), lines)
    visitor.visit(ast.parse(code))
    return visitor.issues


def _selftest_secret_eq_positive() -> None:
    code = (
        "import hmac\n"
        "def verify(password, stored):\n"
        "    return password == stored\n"
    )
    issues = _scan_code(code)
    assert len(issues) == 1, issues
    assert issues[0][1] == 3


def _selftest_ubs_ignore_suppression() -> None:
    code = (
        "def verify(password, stored):\n"
        "    return password == stored  # ubs:ignore\n"
    )
    assert not _scan_code(code)


def _selftest_rule_scoped_suppression_matrix() -> None:
    # GH #154: only a bare marker or one listing this rule suppresses; an
    # unrelated rule scope, a malformed scope, and marker text inside a string
    # literal leave the comparison reported.
    code = (
        "def none(password, provided):\n"
        "    return password == provided\n"
        "def right(password, provided):\n"
        "    return password == provided  # ubs:ignore[python.ctcompare.secret_eq]\n"
        "def wrong(password, provided):\n"
        "    return password == provided  # ubs:ignore[python.taint.sql] -- unrelated\n"
        "def listed(password, provided):\n"
        "    return password == provided  # ubs:ignore[python.taint.sql, python.ctcompare.secret_eq]\n"
        "def bare(password, provided):\n"
        "    return password == provided  # ubs:ignore -- reviewed\n"
        "def in_string(password, provided):\n"
        "    return password == provided or 'ubs:ignore' == provided\n"
        "def malformed(password, provided):\n"
        "    return password == provided  # ubs:ignore[python.ctcompare.secret_eq\n"
    )
    lines = [line for _path, line, _code in _scan_code(code)]
    assert lines == [2, 6, 12, 14], lines


def _selftest_multiline_statement_suppression() -> None:
    # GH #153: a marker on any physical line of the comparison's statement, or
    # a standalone marker directly above the statement, suppresses it; a
    # trailing marker on the previous statement does not.
    code = (
        "def closing(password, provided):\n"
        "    return (\n"
        "        password == provided\n"
        "    )  # ubs:ignore[python.ctcompare.secret_eq] -- closing line\n"
        "def above(password, provided):\n"
        "    # ubs:ignore[python.ctcompare.secret_eq] -- above the statement\n"
        "    return (\n"
        "        password == provided\n"
        "    )\n"
        "def opening(password, provided):\n"
        "    return (  # ubs:ignore[python.ctcompare.secret_eq]\n"
        "        password == provided\n"
        "    )\n"
        "def unrelated_multiline(password, provided):\n"
        "    return (\n"
        "        password == provided\n"
        "    )  # ubs:ignore[python.taint.sql]\n"
        "def previous_statement(password, provided):\n"
        "    other = 1  # ubs:ignore[python.ctcompare.secret_eq]\n"
        "    return password == provided\n"
        "def control(password, provided):\n"
        "    return (\n"
        "        password == provided\n"
        "    )\n"
    )
    lines = [line for _path, line, _code in _scan_code(code)]
    assert lines == [16, 20, 23], lines


def _selftest_run_honours_rule_scoped_markers(tmp_prefix: str = "ubs_core_ctcompare_py_sup_") -> None:
    # The registry path (what `ubs` runs) drops suppressed comparisons at the
    # producer and keeps the unannotated control and the wrong-scope finding.
    import tempfile
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "secrets.py"
        target.write_text(
            "def plain(password, provided):\n"
            "    return password == provided\n"
            "def annotated(password, provided):\n"
            "    return (\n"
            "        password == provided\n"
            "    )  # ubs:ignore[python.ctcompare.secret_eq] -- reviewed\n"
            "def unrelated(password, provided):\n"
            "    return password == provided  # ubs:ignore[python.taint.sql]\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="python", files=[target])))
    assert [(f["rule"], f["line"]) for f in findings] == [
        (RULE_ID, 2), (RULE_ID, 8)
    ], findings


def _selftest_counter_compare_negative() -> None:
    code = (
        "def disabled(total_tokens):\n"
        "    return total_tokens == 0\n"
    )
    assert not _scan_code(code)


def _selftest_hmac_digest_positive() -> None:
    code = (
        "import hmac\n"
        "def valid(sig):\n"
        "    return sig == hmac.new(b'k', b'm', 'sha256').hexdigest()\n"
    )
    issues = _scan_code(code)
    assert len(issues) == 1, issues
    assert issues[0][1] == 3


def _selftest_run_finds_secret_eq(tmp_prefix: str = "ubs_core_ctcompare_py_") -> None:
    import tempfile

    code = (
        "def reset(password, candidate):\n"
        "    return password == candidate\n"
    )
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "secrets.py"
        target.write_text(code, encoding="utf-8")
        findings = list(run(RunContext(lang="python", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "python.ctcompare.secret_eq"
    assert findings[0]["line"] == 2
    assert findings[0]["severity"] == "critical"


def _selftest_public_checksum_negative() -> None:
    # GH #102: an unkeyed digest of public bytes checked against a public
    # manifest is an integrity check, not a secret comparison.
    code = (
        "import hashlib\n"
        "def verify(entry, payload):\n"
        "    if entry['bytes'] != len(payload) or entry['sha256'] != hashlib.sha256(payload).hexdigest():\n"
        "        raise RuntimeError('staging integrity mismatch')\n"
        "    digest = hashlib.new('sha256', payload).hexdigest()\n"
        "    return digest == entry['sha256']\n"
        "def verify_streamed(entry, chunks):\n"
        "    h = hashlib.sha256()\n"
        "    for chunk in chunks:\n"
        "        h.update(chunk)\n"
        "    return h.hexdigest() != entry['sha256']\n"
    )
    assert not _scan_code(code), _scan_code(code)


def _selftest_digest_role_positive() -> None:
    # GH #102 positive controls: keyed MACs, hashes of secret material,
    # secret-fed hash objects and unresolved receivers stay reported.
    code = (
        "import hashlib, hmac\n"
        "def check_tag(key, msg, tag):\n"
        "    return hmac.new(key, msg, 'sha256').hexdigest() == tag\n"
        "def check_blake(key, msg, tag):\n"
        "    return hashlib.blake2b(msg, key=key).hexdigest() == tag\n"
        "def check_password(password, stored_hash):\n"
        "    return hashlib.sha256(password.encode()).hexdigest() == stored_hash\n"
        "def check_streamed(api_key, expected):\n"
        "    h = hashlib.sha256()\n"
        "    h.update(api_key)\n"
        "    return h.hexdigest() == expected\n"
        "def check_unresolved(computed, provided):\n"
        "    return computed.hexdigest() == provided\n"
    )
    issues = _scan_code(code)
    assert [line for _path, line, _code in issues] == [3, 5, 7, 11, 13], issues


def _selftest_code_signature_negative() -> None:
    code = (
        "import signal\n"
        "def dispatch(self, node, completion):\n"
        "    sig = self._call_signature(node)\n"
        "    if sig == ('socket', 'socketpair'):\n"
        "        return 1\n"
        "    if sig[1] == 'closing':\n"
        "        return 2\n"
        "    if self._reference_signature(completion) == ('asyncio', 'ALL_COMPLETED'):\n"
        "        return 3\n"
        "    return signal.getsignal(signal.SIGTERM) == signal.SIG_DFL\n"
    )
    assert not _scan_code(code), _scan_code(code)


def _selftest_signature_positive_controls() -> None:
    code = (
        "import signal\n"
        "def check(request, sig, expected):\n"
        "    webhook_signature = request.headers['X-Signature']\n"
        "    if webhook_signature == expected:\n"
        "        return 1\n"
        "    if sig == expected:\n"
        "        return 2\n"
        "    computed_sig = compute(request.body)\n"
        "    if computed_sig == request.headers['X-Sig']:\n"
        "        return 3\n"
        "    return (sig, 'v1') == (expected, 'v1')\n"
    )
    lines = [line for _path, line, _code in _scan_code(code)]
    assert lines == [4, 6, 9], lines


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("secret_eq_positive", _selftest_secret_eq_positive),
    ("ubs_ignore_suppression", _selftest_ubs_ignore_suppression),
    ("rule_scoped_suppression_matrix", _selftest_rule_scoped_suppression_matrix),
    ("multiline_statement_suppression", _selftest_multiline_statement_suppression),
    ("run_honours_rule_scoped_markers", _selftest_run_honours_rule_scoped_markers),
    ("counter_compare_negative", _selftest_counter_compare_negative),
    ("hmac_digest_positive", _selftest_hmac_digest_positive),
    ("run_finds_secret_eq", _selftest_run_finds_secret_eq),
    ("public_checksum_negative", _selftest_public_checksum_negative),
    ("digest_role_positive", _selftest_digest_role_positive),
    ("code_signature_negative", _selftest_code_signature_negative),
    ("signature_positive_controls", _selftest_signature_positive_controls),
)

register(Analyzer(layer="ctcompare", lang="python", name="ctcompare_py", run=run, selftests=SELF_TESTS))
