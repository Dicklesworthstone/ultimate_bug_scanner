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

Structural role (GH #195): a resolved local method returning a public tuple
can be an analysis-state fingerprint. The method body and receiver contract
must both support that role; an unresolved ``signature()`` is still sensitive.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Iterable, NamedTuple

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import build_index
from ubs_core.taint_flow import AnalysisLimit

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
    if isinstance(target, ast.Starred):
        return target_names(target.value)
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


class StructuralFingerprints(ast.NodeVisitor):
    """Resolve a small, closed set of public tuple-producing local methods.

    An annotation alone never proves a return value public: the local class
    must have an ordinary, undecorated method with a single tuple return made
    from non-secret fields and structural builtins. Unknown calls, inheritance,
    descriptors, rebinding and namespace reflection defeat the proof. Typed
    parameters and container fields express receiver contracts; assignments
    cannot replace those contracts with unknown values unnoticed.
    """

    def __init__(self, tree):
        self.public = set()
        self.env = {}
        self.owner = None
        self.direct = set(tree.body)
        self.writes = {}
        self.classes = {}
        self.fields = {}
        self.methods = set()
        self.record_fields = {}
        self.literal_names = set()
        self.field_names = set()
        nodes = list(ast.walk(tree))
        reflection = {
            'getattr', 'setattr', 'delattr', 'vars', 'globals', 'locals', 'eval',
            'exec', '__dict__', '__getattribute__', '__getattr__', '__setattr__',
            '_getframe', 'currentframe', 'f_globals', 'f_locals', '__builtins__',
        }
        if any(
            isinstance(node, ast.Name) and node.id in reflection
            or isinstance(node, ast.Attribute) and node.attr in reflection
            or isinstance(node, ast.alias) and node.name.rsplit('.', 1)[-1] in reflection
            for node in nodes
        ):
            return
        writes = self.binding_counts(nodes)
        self.all_writes = writes
        secret_fields, secret_constructors = set(), set()
        for scope in nodes:
            if not isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            local_nodes = self.lexical_nodes(scope)
            assignments = [item for item in local_nodes if isinstance(item, (ast.Assign, ast.AnnAssign, ast.NamedExpr))]
            secret_aliases = set()
            field_aliases = {}

            def secret_value(value):
                return value is not None and any(
                    isinstance(part, ast.Name) and (part.id in secret_aliases or name_is_sensitive(part.id))
                    or isinstance(part, ast.Attribute) and name_is_sensitive(part.attr)
                    for part in ast.walk(value)
                )

            changed = True
            while changed:
                before = len(secret_aliases), sum(map(len, field_aliases.values()))
                for item in assignments:
                    targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                    if secret_value(item.value):
                        secret_aliases.update(name for target in targets for name in target_names(target))
                    if isinstance(item.value, (ast.Name, ast.Attribute, ast.Subscript)):
                        fields = {part.attr for part in ast.walk(item.value) if isinstance(part, ast.Attribute)}
                        for part in ast.walk(item.value):
                            if isinstance(part, ast.Name):
                                fields.update(field_aliases.get(part.id, ()))
                        for target in targets:
                            for name in target_names(target):
                                field_aliases.setdefault(name, set()).update(fields)
                changed = (len(secret_aliases), sum(map(len, field_aliases.values()))) != before
            secret_fields.update(
                part.attr for item in assignments if secret_value(item.value)
                for target in (item.targets if isinstance(item, ast.Assign) else [item.target])
                for part in ast.walk(target) if isinstance(part, ast.Attribute)
            )
            # A typed callee must not re-certify a field that its caller filled
            # with a secret through a local mutable alias (fields = state.values).
            secret_fields.update(
                field for item in assignments if secret_value(item.value)
                for target in (item.targets if isinstance(item, ast.Assign) else [item.target])
                for access in ast.walk(target) if isinstance(access, (ast.Attribute, ast.Subscript))
                for part in ast.walk(access) if isinstance(part, ast.Name)
                for field in field_aliases.get(part.id, ())
            )
            secret_constructors.update(
                item.func.id for item in local_nodes if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
                and any(secret_value(value) for value in [*item.args, *(kw.value for kw in item.keywords)])
            )
        annotations = set()
        for item in nodes:
            annotation = (item.annotation if isinstance(item, (ast.arg, ast.AnnAssign))
                          else item.returns if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) else None)
            if annotation is not None:
                annotations.update(ast.walk(annotation))
        module_writes = self.binding_counts(self.lexical_nodes(tree))
        parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
        self.parents = parents
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    names = target_names(target)
                    values = (statement.value.elts if isinstance(statement.value, ast.Tuple)
                              and isinstance(target, ast.Tuple) else [statement.value])
                    if len(names) == len(values):
                        self.literal_names.update(name for name, value in zip(names, values)
                                                  if isinstance(value, ast.Constant) and self.public_default(value, writes)
                                                  and writes.get(name) == 1)
        replaced = {
            node.attr for node in nodes
            if isinstance(node, ast.Attribute) and not isinstance(node.ctx, ast.Load)
        }
        inherited = {
            base.id for node in nodes if isinstance(node, ast.ClassDef)
            for base in node.bases if isinstance(base, ast.Name)
        }
        dataclass_names = {
            item.asname or item.name for statement in tree.body
            if isinstance(statement, ast.ImportFrom) and statement.module == 'dataclasses'
            for item in statement.names if item.name == 'dataclass'
        }
        self.field_names = {
            item.asname or item.name for statement in tree.body
            if isinstance(statement, ast.ImportFrom) and statement.module == 'dataclasses'
            for item in statement.names
            if item.name == 'field' and module_writes.get(item.asname or item.name) == 1
        }
        for node in tree.body:
            if (not isinstance(node, ast.ClassDef) or writes.get(node.name) != 1
                    or node.name in secret_constructors):
                continue
            decorators = [value.func if isinstance(value, ast.Call) else value
                          for value in node.decorator_list]
            if node.bases or node.keywords or node.name in inherited or any(
                not isinstance(value, ast.Name) or value.id not in dataclass_names
                or writes.get(value.id) != 1 for value in decorators
            ):
                continue
            if any(isinstance(value, ast.Call) and (value.args or any(
                not isinstance(keyword.value, ast.Constant) or not isinstance(keyword.value.value, bool)
                for keyword in value.keywords
            )) for value in node.decorator_list):
                continue
            # A class passed as a value can be monkey-patched by unknown code.
            if any(isinstance(item, ast.Name) and item.id == node.name
                   and isinstance(item.ctx, ast.Load) and item not in annotations
                   and not (isinstance(parents.get(item), ast.Call) and parents[item].func is item)
                   for item in nodes):
                continue
            # A property can compute a secret even when its name is innocuous.
            if any(isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and (item.name in {'__getattribute__', '__getattr__', '__new__'} or any(
                       not isinstance(value, ast.Name) or value.id not in {'staticmethod', 'classmethod'}
                       for value in item.decorator_list
                   )) for item in node.body):
                continue
            self.classes[node.name] = node
            self.record_fields[node.name] = {
                item.target.id: item for item in node.body
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
            }
            class_bindings = {
                name for item in node.body if isinstance(item, ast.Assign)
                for target in item.targets for name in target_names(target)
            } | set(self.record_fields[node.name])
            if self.field_names.intersection(class_bindings):
                self.record_fields[node.name] = {}
            if secret_fields.intersection(self.record_fields[node.name]):
                self.record_fields[node.name] = {}
        for name, node in self.classes.items():
            fields = {}
            for item in ast.walk(node):
                if isinstance(item, ast.AnnAssign):
                    if isinstance(item.target, ast.Name):
                        fields[item.target.id] = item.annotation
                    elif isinstance(item.target, ast.Attribute) and isinstance(item.target.value, ast.Name):
                        if item.target.value.id == 'self':
                            fields[item.target.attr] = item.annotation
            self.fields[name] = fields
            if not self.public_record(name, writes, set()):
                continue
            for method in node.body:
                if (not isinstance(method, ast.FunctionDef) or method.name in replaced
                        or method.decorator_list):
                    continue
                terms = set(identifier_terms(method.name)) - CODE_SIGNATURE_TERMS
                if terms.intersection(STRONG_TERMS | WEAK_TERMS | QUALIFIER_TERMS):
                    continue
                args = method.args.posonlyargs + method.args.args
                body = [item for item in method.body if not (
                    isinstance(item, ast.Expr) and isinstance(item.value, ast.Constant)
                    and isinstance(item.value.value, str)
                )]
                if (len(args) == 1 and not method.args.kwonlyargs
                        and not method.args.vararg and not method.args.kwarg
                        and len(body) == 1 and isinstance(body[0], ast.Return)
                        and isinstance(body[0].value, ast.Tuple)
                        and self.public_expression(body[0].value, args[0].arg, writes, name)
                        and any(isinstance(item, ast.Attribute) and item.attr in fields
                                and any(isinstance(part, ast.Name) and part.id in self.classes
                                        for part in ast.walk(fields[item.attr]))
                                for item in ast.walk(body[0].value))):
                    self.methods.add((name, method.name))
        self.writes = self.binding_counts(nodes)
        if self.methods:
            self.visit(tree)

    @staticmethod
    def lexical_nodes(root):
        nodes = []
        pending = list(ast.iter_child_nodes(root))
        while pending:
            item = pending.pop()
            nodes.append(item)
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                pending.extend(ast.iter_child_nodes(item))
        return nodes

    @staticmethod
    def binding_counts(nodes):
        counts = {}
        for node in nodes:
            name = None
            if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
                name = node.id
            elif isinstance(node, ast.arg):
                name = node.arg
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = node.name
            elif isinstance(node, ast.alias):
                name = node.asname or node.name.split('.')[0]
            elif isinstance(node, ast.ExceptHandler):
                name = node.name
            elif isinstance(node, tuple(getattr(ast, kind) for kind in (
                'MatchAs', 'MatchStar', 'TypeVar', 'ParamSpec', 'TypeVarTuple',
            ) if hasattr(ast, kind))):
                name = node.name
            elif isinstance(node, getattr(ast, 'MatchMapping', ())):
                name = node.rest
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                for value in node.names:
                    counts[value] = counts.get(value, 0) + 2
            if name:
                counts[name] = counts.get(name, 0) + 1
        return counts

    def public_default(self, node, writes):
        if isinstance(node, ast.Constant):
            return node.value is None or isinstance(node.value, (bool, int, float)) or node.value == ''
        if isinstance(node, ast.Name):
            return node.id in self.literal_names
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {'dict', 'list', 'set', 'tuple', 'frozenset'}:
                return node.func.id not in writes and not node.args and not node.keywords
            if node.func.id in self.field_names and not node.args:
                return bool(node.keywords) and all(
                    keyword.arg == 'default_factory' and isinstance(keyword.value, ast.Name)
                    and keyword.value.id in {'dict', 'list', 'set', 'tuple', 'frozenset'}
                    and keyword.value.id not in writes
                    or keyword.arg == 'default' and self.public_default(keyword.value, writes)
                    for keyword in node.keywords
                )
        return False

    def public_annotation(self, node, writes, active, field=''):
        if isinstance(node, ast.Name):
            metadata = {term.rstrip('s') for term in identifier_terms(field)}
            return (node.id in {'int', 'float', 'bool'} and node.id not in writes
                    or node.id == 'str' and node.id not in writes
                    and bool(metadata.intersection(METADATA_TERMS | {'exit', 'origin', 'path', 'identifier'}))
                    or self.public_record(node.id, writes, active))
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            if node.value.id in {'dict', 'list', 'set', 'tuple', 'frozenset'} and node.value.id not in writes:
                items = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
                return all(self.public_annotation(item, writes, active,
                                                  'name' if node.value.id == 'dict' and index == 0 else field)
                           for index, item in enumerate(items))
        return False

    def public_record(self, name, writes, active):
        fields = self.record_fields.get(name, {})
        if not fields or name in active or any(
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in {'__init__', '__post_init__'}
            for item in self.classes[name].body
        ):
            return False
        return all(not name_is_sensitive(field) and self.public_default(item.value, writes)
                   and self.public_annotation(item.annotation, writes, active | {name}, field)
                   for field, item in fields.items())

    def public_expression(self, node, receiver, writes, owner):
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return all(self.public_expression(item, receiver, writes, owner) for item in node.elts)
        if isinstance(node, ast.Attribute):
            return (isinstance(node.value, ast.Name) and node.value.id == receiver
                    and node.attr in self.record_fields[owner])
        if isinstance(node, ast.Call) and not node.keywords:
            if isinstance(node.func, ast.Name) and node.func.id in {'tuple', 'sorted', 'frozenset'}:
                return (node.func.id not in writes and len(node.args) == 1
                        and self.public_expression(node.args[0], receiver, writes, owner))
            if isinstance(node.func, ast.Attribute) and node.func.attr in {'items', 'keys', 'values'}:
                return not node.args and self.public_expression(node.func.value, receiver, writes, owner)
        return False

    def annotation_type(self, node):
        if isinstance(node, ast.Name) and node.id in self.classes:
            return ('instance', node.id)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            if node.value.id in {'list', 'set', 'frozenset'} and node.value.id not in self.all_writes:
                element = self.annotation_type(node.slice)
                return ('sequence', element) if element else None
        return None

    def value_type(self, node):
        if isinstance(node, ast.Name):
            return self.env.get(node.id) or (('secret', None) if name_is_sensitive(node.id) else None)
        if isinstance(node, ast.Attribute):
            receiver = self.value_type(node.value)
            if receiver and receiver[0] == 'instance':
                return self.annotation_type(self.fields.get(receiver[1], {}).get(node.attr))
        if isinstance(node, ast.Subscript):
            receiver = self.value_type(node.value)
            if receiver and receiver[0] == 'sequence' and not isinstance(node.slice, ast.Slice):
                return receiver[1]
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in self.classes:
                # Defaults were checked with the record body. Arbitrary
                # constructor inputs need deeper field provenance than this
                # bounded role proof supplies, even when their names are plain.
                if not node.args and not node.keywords:
                    return ('instance', node.func.id)
            if isinstance(node.func, ast.Attribute) and not node.args and not node.keywords:
                receiver = self.value_type(node.func.value)
                if (receiver and (receiver[1], node.func.attr) in self.methods
                        and not name_is_sensitive(call_name(node.func.value))):
                    return ('fingerprint', None)
        if node is not None and any(
            isinstance(part, ast.Name) and self.value_type(part) == ('secret', None)
            or isinstance(part, ast.Attribute) and name_is_sensitive(part.attr)
            for part in ast.walk(node)
        ):
            return ('secret', None)
        return None

    def visit_ClassDef(self, node):
        old_owner = self.owner
        self.owner = node.name if node.name in self.classes else None
        for statement in node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.visit(statement)
        self.owner = old_owner

    def visit_FunctionDef(self, node):
        previous = self.env, self.writes, self.direct
        self.env = {}
        self.writes = self.binding_counts(ast.walk(node))
        self.direct = set(node.body)
        args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        method = self.owner and node in self.classes[self.owner].body
        for index, arg in enumerate(args):
            if self.writes.get(arg.arg) == 1:
                terms = identifier_terms(arg.arg)
                sensitive = (name_is_sensitive(arg.arg)
                             or name_is_sensitive('_'.join(term[:-1] if term.endswith('s') else term
                                                           for term in terms)))
                self.env[arg.arg] = (('secret', None) if sensitive
                                    else ('instance', self.owner) if index == 0 and method
                                    else self.annotation_type(arg.annotation))
        for statement in node.body:
            self.visit(statement)
        self.env, self.writes, self.direct = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        old_env = self.env
        self.env = {}
        self.visit(node.body)
        self.env = old_env

    def visit_Assign(self, node):
        self.visit(node.value)
        if (isinstance(node.value, (ast.List, ast.Tuple, ast.Set, ast.Dict))
                or self.value_type(node.value) is None):
            self.invalidate_receivers([node.value])
        value = self.value_type(node.value) if node in self.direct else None
        for target in node.targets:
            if isinstance(target, (ast.Attribute, ast.Subscript)):
                self.invalidate_receivers([target])
            for name in target_names(target):
                self.env[name] = value if self.writes.get(name) == 1 else None

    def visit_AnnAssign(self, node):
        if node.value:
            self.visit(node.value)
            if (isinstance(node.value, (ast.List, ast.Tuple, ast.Set, ast.Dict))
                    or self.value_type(node.value) is None):
                self.invalidate_receivers([node.value])
        if isinstance(node.target, ast.Name):
            self.env[node.target.id] = (
                self.value_type(node.value)
                if node in self.direct and self.writes.get(node.target.id) == 1 else None
            )
        else:
            self.invalidate_receivers([node.target])

    def visit_AugAssign(self, node):
        self.visit(node.value)
        self.invalidate_receivers([node.target])

    def visit_Delete(self, node):
        self.invalidate_receivers(node.targets)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load) and self.env.get(node.id) == ('fingerprint', None):
            # A public tuple cannot explain an independently security-qualified name.
            terms = set(identifier_terms(node.id)) - CODE_SIGNATURE_TERMS
            if not terms.intersection(STRONG_TERMS | WEAK_TERMS | QUALIFIER_TERMS):
                self.public.add(node)

    def visit_Call(self, node):
        public = self.value_type(node) == ('fingerprint', None)
        if public:
            self.public.add(node)
        self.generic_visit(node)
        if self.reads_length(node):
            return  # builtin len does not mutate a typed builtin container
        arguments = [*node.args, *(item.value for item in node.keywords)]
        if not public and isinstance(node.func, ast.Attribute):
            arguments.append(node.func.value)
        self.invalidate_receivers(arguments)

    def reads_length(self, node):
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'len'
                and 'len' not in self.all_writes and len(node.args) == 1 and not node.keywords
                and (value := self.value_type(node.args[0])) and value[0] == 'sequence')

    def invalidate_receivers(self, expressions):
        escaped = set()
        pending = list(expressions)
        while pending:
            part = pending.pop()
            if self.reads_length(part):
                continue
            if isinstance(part, ast.Name) and (value := self.env.get(part.id)):
                if value[0] in {'instance', 'sequence'}:
                    escaped.add(value)
            pending.extend(ast.iter_child_nodes(part))
        if escaped:
            self.env = {name: None if value in escaped else value for name, value in self.env.items()}

    def visit_GeneratorExp(self, node):
        old_env = self.env
        self.env = dict(old_env)
        if isinstance(node, ast.GeneratorExp):
            parent = self.parents.get(node)
            if not (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name)
                    and parent.func.id in {'all', 'any'} and parent.func.id not in self.all_writes
                    and len(parent.args) == 1 and not parent.keywords):
                # Deferred generators can run after a receiver changes. Only
                # the eager builtin consumers justify the current environment.
                self.env = {}
        local_names = set()
        for generator in node.generators:
            self.visit(generator.iter)
            value = self.value_type(generator.iter)
            for name in target_names(generator.target):
                local_names.add(name)
                self.env[name] = (value[1] if value and value[0] == 'sequence'
                                  and isinstance(generator.target, ast.Name) else None)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        for name, value in old_env.items():
            if name not in local_names and self.env.get(name) != value:
                old_env[name] = None
        self.env = old_env

    visit_ListComp = visit_GeneratorExp
    visit_SetComp = visit_GeneratorExp
    visit_DictComp = visit_GeneratorExp


def local_unkeyed_digest_helpers(tree):
    """Resolve a stable, one-argument wrapper around an unkeyed hashlib call.

    This gives local checksum helpers the same input-sensitive role as the
    direct hashlib expression. Unknown helper bodies and rebinding retain the
    conservative fallback; a reassuring name is never the evidence.
    """
    nodes = list(ast.walk(tree))
    writes = StructuralFingerprints.binding_counts(nodes)
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    reflection = {
        'getattr', 'setattr', 'delattr', 'vars', 'globals', 'locals', 'eval', 'exec',
        '__dict__', '__code__', '__getattribute__', '__getattr__', '__setattr__', '__builtins__',
        '__globals__', 'modules', 'import_module',
        '_getframe', 'currentframe', 'f_globals', 'f_locals',
    }
    if any(
        (node.id if isinstance(node, ast.Name) else
         node.attr if isinstance(node, ast.Attribute) else
         node.name.rsplit('.', 1)[-1] if isinstance(node, ast.alias) else '') in reflection
        for node in nodes
    ):
        return {}
    if any(isinstance(node, ast.ImportFrom) and any(alias.name == '*' for alias in node.names)
           for node in nodes):
        return {}  # wildcard imports can replace otherwise single-write bindings
    modules, constructors = set(), set()
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            modules.update(alias.asname or alias.name for alias in statement.names
                           if alias.name == 'hashlib' and writes.get(alias.asname or alias.name) == 1)
        if (isinstance(statement, ast.ImportFrom) and not statement.level
                and statement.module == 'hashlib'):
            constructors.update(alias.asname or alias.name for alias in statement.names
                                if alias.name in UNKEYED_HASH_CTORS
                                and writes.get(alias.asname or alias.name) == 1)
    # An escaped module or a rewritten member no longer has a known binding.
    modules.difference_update(
        node.id for node in nodes if isinstance(node, ast.Name) and node.id in modules
        and isinstance(node.ctx, ast.Load) and not isinstance(parents.get(node), ast.Attribute)
    )
    modules.difference_update(
        node.value.id for node in nodes if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name) and not isinstance(node.ctx, ast.Load)
    )
    result = {}
    for function in tree.body:
        if (not isinstance(function, ast.FunctionDef) or writes.get(function.name) != 1
                or function.decorator_list):
            continue
        args = function.args
        positional = args.posonlyargs + args.args
        if (len(positional) != 1 or args.defaults or args.kwonlyargs or args.vararg or args.kwarg):
            continue
        body = [statement for statement in function.body if not (
            isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        )]
        if len(body) != 1 or not isinstance(body[0], ast.Return):
            continue
        value = body[0].value
        if not (isinstance(value, ast.Call) and not value.args and not value.keywords
                and isinstance(value.func, ast.Attribute) and value.func.attr in {'digest', 'hexdigest'}):
            continue
        constructor = value.func.value
        if not (isinstance(constructor, ast.Call) and len(constructor.args) == 1 and not constructor.keywords
                and isinstance(constructor.args[0], ast.Name) and constructor.args[0].id == positional[0].arg):
            continue
        callee = constructor.func
        known = (isinstance(callee, ast.Name) and callee.id in constructors
                 or isinstance(callee, ast.Attribute) and isinstance(callee.value, ast.Name)
                 and callee.value.id in modules and callee.attr in UNKEYED_HASH_CTORS)
        if not known:
            continue
        if any(isinstance(node, ast.Name) and node.id == function.name and isinstance(node.ctx, ast.Load)
               and not (isinstance(parents.get(node), ast.Call) and parents[node].func is node)
               for node in nodes):
            continue  # unknown code can replace an escaped helper's implementation
        result[function.name] = positional[0].arg
    return result


class ComparisonValue(NamedTuple):
    sensitive: bool
    container: bool
    hashes: frozenset
    elements: frozenset
    public_hash: bool = False
    collections: frozenset = frozenset()
    selector: tuple = ()
    methods: frozenset = frozenset()


class HashReferences(NamedTuple):
    objects: frozenset = frozenset()
    collections: frozenset = frozenset()
    methods: frozenset = frozenset()
    selector: tuple = ()


class CapturedHashMethod(NamedTuple):
    name: str
    receiver: HashReferences


class HashCollection(NamedTuple):
    kind: str
    slots: tuple
    unknown: HashReferences = HashReferences()
    length: int | None = None
    keys: HashReferences = HashReferences()
    present: frozenset = frozenset()


class ComparisonScope(NamedTuple):
    names: set
    before: tuple
    mutations: set


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
        self.unkeyed_digest_helpers = {}
        self.sensitive_containers = set()
        self.exception_entries = []
        # Names bound to an unkeyed hashlib object fed only non-secret data
        # (GH #102): their .digest()/.hexdigest() is a checksum, not a tag.
        self.unkeyed_hash_names = set()
        # Names whose secret-looking spelling is explained by a non-secret
        # binding (`sig = self._call_signature(node)`).
        self.explained_names = set()
        self.public_signal_bindings = {}
        self.structural_values = set()
        self.expression_values = {}
        self.comprehension_values = {}
        # Allocation identities only invalidate proofs; an alias alone does
        # not establish that an unknown receiver is a public hashlib object.
        self.hash_objects = {}
        self.hash_elements = {}
        # Literal collections keep reference identity separately from the
        # aggregate sensitivity vocabulary. Only the selected slot aliases a
        # hash: changing its neighbor must not revoke that hash's public role.
        self.hash_collections = {}
        self.scalar_names = {}
        self.bound_methods = {}
        self.collection_heap = {}
        self.repeated_evaluation = 0
        self.repeated_hash_sites = set()
        self.incomplete_reasons = set()
        self.call_references = {}
        self.expression_scopes = []
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

    def require_complete(self):
        if self.incomplete_reasons:
            raise AnalysisLimit('; '.join(sorted(self.incomplete_reasons)), effects={'findings': tuple(self.issues)})

    def expr_is_sensitive(self, node):
        if node in self.structural_values:
            return False
        if node in self.expression_values:
            return self.expression_values[node].sensitive
        if node in self.comprehension_values:
            return not isinstance(node, ast.GeneratorExp) and self.comprehension_values[node].sensitive
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
            if isinstance(node.func, ast.Name) and node.func.id in self.unkeyed_digest_helpers:
                parameter = self.unkeyed_digest_helpers[node.func.id]
                shape = (len(node.args) == 1 and not isinstance(node.args[0], ast.Starred) and not node.keywords
                         or not node.args and len(node.keywords) == 1 and node.keywords[0].arg == parameter)
                return self.call_input_is_sensitive(node) if shape else True
            if short in {'digest', 'hexdigest'}:
                if isinstance(node.func, ast.Attribute):
                    return self.digest_is_sensitive(node.func.value)
                return True  # bare digest(...): provenance unknown, keep reporting
            return False
        if isinstance(node, ast.BinOp):
            return self.expr_is_sensitive(node.left) or self.expr_is_sensitive(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self.expr_is_sensitive(value) for value in node.values)
        if isinstance(node, ast.IfExp):
            return self.expr_is_sensitive(node.body) or self.expr_is_sensitive(node.orelse)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return any(self.expr_is_sensitive(value) for value in node.elts)
        if isinstance(node, ast.Dict):
            return any(self.expr_is_sensitive(value) for value in [*node.keys, *node.values] if value is not None)
        if isinstance(node, ast.Starred):
            return self.expr_is_sensitive(node.value)
        if isinstance(node, ast.NamedExpr):
            return self.expr_is_sensitive(node.value)
        return False

    def expr_has_sensitive_container(self, node):
        if node in self.expression_values:
            return self.expression_values[node].container
        if node in self.comprehension_values:
            return self.comprehension_values[node].sensitive
        if isinstance(node, ast.Name):
            return node.id in self.sensitive_containers
        if isinstance(node, (ast.Tuple, ast.List, ast.Set, ast.Dict)):
            return self.expr_is_sensitive(node)
        if isinstance(node, ast.IfExp):
            return self.expr_has_sensitive_container(node.body) or self.expr_has_sensitive_container(node.orelse)
        if isinstance(node, ast.NamedExpr):
            return self.expr_has_sensitive_container(node.value)
        return False

    @staticmethod
    def merge_references(*references):
        return HashReferences(
            frozenset().union(*(value.objects for value in references)),
            frozenset().union(*(value.collections for value in references)),
            frozenset().union(*(value.methods for value in references)),
            references[0].selector if references and references[0].selector
            and all(value.selector == references[0].selector for value in references) else ())

    def collection_key(self, node):
        if node in self.expression_values:
            selector = self.expression_values[node].selector
            return (True, selector[0]) if selector else (False, None)
        if isinstance(node, ast.Name):
            selector = self.scalar_names.get(node.id, ())
            return (True, selector[0]) if selector else (False, None)
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int, float, type(None))):
            return True, node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            known, value = self.collection_key(node.operand)
            if known and isinstance(value, (int, float)):
                return True, -value if isinstance(node.op, ast.USub) else value
        if isinstance(node, ast.NamedExpr):
            return self.collection_key(node.value)
        if isinstance(node, ast.Subscript):
            selector = self.projected_references(node).selector
            return (True, selector[0]) if selector else (False, None)
        if node in self.call_references:
            selector = self.call_references[node].selector
            return (True, selector[0]) if selector else (False, None)
        if isinstance(node, ast.Tuple):
            values = [self.collection_key(value) for value in node.elts]
            if all(known for known, _value in values):
                return True, tuple(value for _known, value in values)
        if isinstance(node, ast.BinOp):
            return self.combine_selectors(node.op, self.collection_key(node.left), self.collection_key(node.right))
        return False, None

    @staticmethod
    def combine_selectors(operator, left, right):
        if not (left[0] and right[0]):
            return False, None
        first, second = left[1], right[1]
        numeric = isinstance(first, (int, float)) and isinstance(second, (int, float))
        if isinstance(operator, ast.Add) and (numeric or isinstance(first, (str, bytes)) and type(first) is type(second)):
            return True, first + second
        if isinstance(operator, ast.Sub) and numeric:
            return True, first - second
        return False, None

    def value_collections(self, node):
        if node in self.expression_values:
            return self.expression_values[node].collections
        if isinstance(node, ast.Name):
            return self.hash_collections.get(node.id, frozenset())
        if node in self.collection_heap:
            return frozenset((node,))
        if node in self.call_references:
            return self.call_references[node].collections
        if isinstance(node, (ast.NamedExpr, ast.Starred)):
            return self.value_collections(node.value)
        if isinstance(node, ast.IfExp):
            return self.value_collections(node.body) | self.value_collections(node.orelse)
        if isinstance(node, ast.Subscript):
            return self.projected_references(node).collections
        return frozenset()

    def value_references(self, node):
        known, selector = self.collection_key(node)
        return HashReferences(self.value_hashes(node), self.value_collections(node), self.value_methods(node),
                              (selector,) if known else ())

    def value_methods(self, node):
        if node in self.expression_values:
            return self.expression_values[node].methods
        if node in self.call_references:
            return self.call_references[node].methods
        if isinstance(node, ast.Name):
            return self.bound_methods.get(node.id, frozenset())
        if isinstance(node, ast.Attribute) and node.attr in {
            'update', 'append', 'extend', 'insert', 'pop', 'clear', 'reverse',
            'copy', 'get', 'setdefault', '__setitem__', '__delitem__',
        }:
            receiver = HashReferences(self.value_hashes(node.value), self.value_collections(node.value))
            if receiver.objects or receiver.collections:
                return frozenset((CapturedHashMethod(node.attr, receiver),))
        if isinstance(node, ast.Subscript):
            return self.projected_references(node).methods
        if isinstance(node, (ast.NamedExpr, ast.Starred)):
            return self.value_methods(node.value)
        if isinstance(node, ast.IfExp):
            return self.value_methods(node.body) | self.value_methods(node.orelse)
        return frozenset()

    def collection_references(self, collections, *, iteration=False):
        values = []
        for identity in collections:
            shape = self.collection_heap.get(identity)
            if shape is None:
                continue
            if iteration and shape.kind == 'dict':
                values.append(shape.keys)
            else:
                values.extend(value for _key, value in shape.slots)
                values.append(shape.unknown)
                if not iteration:
                    values.append(shape.keys)
        return self.merge_references(*values)

    def contained_hashes(self, collections):
        pending, seen, objects = set(collections), set(), set()
        while pending:
            identity = pending.pop()
            if identity in seen:
                continue
            seen.add(identity)
            references = self.collection_references((identity,))
            objects.update(references.objects)
            pending.update(references.collections - seen)
        return frozenset(objects)

    def selected_references(self, shape, known, key):
        if shape.kind in {'list', 'tuple'} and known:
            if not isinstance(key, int):
                return HashReferences()
            if key < 0:
                if shape.length is None:
                    known = False
                else:
                    key += shape.length
            if known and shape.length is not None and not 0 <= key < shape.length:
                return HashReferences()
        if known:
            return dict(shape.slots).get(key, shape.unknown)
        return self.merge_references(shape.unknown, *(value for _key, value in shape.slots))

    def projected_references(self, node):
        if isinstance(node.slice, ast.Slice):
            # A slice returns a collection, not one of its hash objects.
            return HashReferences(collections=frozenset((node,))) if node in self.collection_heap else HashReferences()
        known, key = self.collection_key(node.slice)
        return self.merge_references(*(
            self.selected_references(self.collection_heap[identity], known, key)
            for identity in self.value_collections(node.value) if identity in self.collection_heap))

    def merge_collection_heaps(self, *heaps):
        result = {}
        for identity in set().union(*(set(heap) for heap in heaps)):
            shapes = [heap[identity] for heap in heaps if identity in heap]
            if len(shapes) == 1:
                result[identity] = shapes[0]
                continue
            keys = dict.fromkeys(key for shape in shapes for key, _value in shape.slots)
            slots = tuple((key, self.merge_references(*(
                self.selected_references(shape, True, key) for shape in shapes))) for key in keys)
            lengths = {shape.length for shape in shapes}
            result[identity] = HashCollection(
                shapes[0].kind, slots, self.merge_references(*(shape.unknown for shape in shapes)),
                next(iter(lengths)) if len(lengths) == 1 else None,
                self.merge_references(*(shape.keys for shape in shapes)),
                frozenset.intersection(*(shape.present for shape in shapes)))
        return result

    def value_hashes(self, node, elements=False):
        collections = self.value_collections(node) if elements else frozenset()
        if collections:
            return self.contained_hashes(collections)
        if node in self.expression_values:
            value = self.expression_values[node]
            return value.elements if elements else value.hashes
        if node in self.call_references:
            return frozenset() if elements else self.call_references[node].objects
        if node in self.comprehension_values:
            return self.comprehension_values[node].elements if elements else frozenset()
        if isinstance(node, ast.Name):
            bindings = self.hash_elements if elements else self.hash_objects
            return bindings.get(node.id, frozenset())
        if isinstance(node, ast.Call) and self.is_unkeyed_hash_ctor(node):
            return frozenset() if elements else frozenset((node,))
        if isinstance(node, (ast.NamedExpr, ast.Starred)):
            return self.value_hashes(node.value, elements)
        if isinstance(node, ast.IfExp):
            return self.value_hashes(node.body, elements) | self.value_hashes(node.orelse, elements)
        if isinstance(node, ast.Subscript):
            return frozenset() if elements else self.projected_references(node).objects
        if elements and isinstance(node, (ast.Tuple, ast.List, ast.Set, ast.Dict)):
            values = [*node.keys, *node.values] if isinstance(node, ast.Dict) else node.elts
            return frozenset().union(*(self.value_hashes(value) | self.value_hashes(value, True)
                                       for value in values if value is not None))
        return frozenset()

    def public_hash_value(self, node):
        if node in self.expression_values:
            return self.expression_values[node].public_hash
        if isinstance(node, ast.Name):
            return node.id in self.unkeyed_hash_names
        return (isinstance(node, ast.Call) and self.is_unkeyed_hash_ctor(node)
                and not self.call_input_is_sensitive(node))

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
            return not self.public_hash_value(receiver)
        return True

    def mark_assignment(self, names, value):
        value_sensitive = self.expr_is_sensitive(value)
        container_sensitive = self.expr_has_sensitive_container(value)
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
            if container_sensitive:
                self.sensitive_containers.add(name)
            else:
                self.sensitive_containers.discard(name)
            self.hash_objects[name] = self.value_hashes(value)
            self.hash_elements[name] = self.value_hashes(value, True)
            self.hash_collections[name] = self.value_collections(value)
            known, selector = self.collection_key(value)
            self.scalar_names[name] = (selector,) if known else ()
            self.bound_methods[name] = self.value_methods(value)

    def comparison_state(self):
        return (set(self.sensitive_names), set(self.unkeyed_hash_names),
                set(self.explained_names), set(self.sensitive_containers),
                dict(self.hash_objects), dict(self.hash_elements),
                dict(self.hash_collections), dict(self.scalar_names),
                dict(self.bound_methods), dict(self.collection_heap))

    @staticmethod
    def merge_hash_bindings(*bindings):
        result = {}
        for incoming in bindings:
            for name, objects in incoming.items():
                result[name] = result.get(name, frozenset()) | objects
        return result

    @staticmethod
    def merge_scalar_bindings(*bindings):
        return {name: bindings[0][name]
                for name in set.intersection(*(set(incoming) for incoming in bindings))
                if bindings[0][name] and all(incoming[name] == bindings[0][name] for incoming in bindings)}

    @staticmethod
    def project_scope(state, scope):
        for current, original in zip(state[:4], scope.before[:4]):
            current.difference_update(scope.names)
            current.update(original & scope.names)
        for current, original in zip(state[4:9], scope.before[4:9]):
            for name in scope.names:
                current.pop(name, None)
                if name in original:
                    current[name] = original[name]
        # Restoring a local name must not restore a hash object that a
        # captured alias mutated while that name was shadowed.
        state[1].difference_update(name for name, objects in state[4].items()
                                   if objects & scope.mutations)
        return state

    def record_exception_entry(self, state):
        if self.exception_entries:
            for scope in reversed(self.expression_scopes):
                self.project_scope(state, scope)
            incoming = self.exception_entries[-1]
            incoming[0].update(state[0])
            incoming[1].intersection_update(state[1])
            incoming[2].intersection_update(state[2])
            incoming[3].update(state[3])
            for index in (4, 5, 6, 8):
                incoming[index].update(self.merge_hash_bindings(incoming[index], state[index]))
            selectors = self.merge_scalar_bindings(incoming[7], state[7])
            incoming[7].clear()
            incoming[7].update(selectors)
            incoming[9].update(self.merge_collection_heaps(incoming[9], state[9]))

    def visit(self, node):
        # An exception can leave a statement before its normal assignments
        # complete. Include nested statements, not only a try body's endpoint.
        statement = isinstance(node, ast.stmt)
        expression = isinstance(node, ast.expr)
        if expression:
            self.expression_values.pop(node, None)
            self.call_references.pop(node, None)
        if statement and self.exception_entries:
            self.record_exception_entry(self.comparison_state())
        result = super().visit(node)
        if expression:
            known, selector = self.collection_key(node)
            self.expression_values[node] = ComparisonValue(
                self.expr_is_sensitive(node), self.expr_has_sensitive_container(node),
                self.value_hashes(node), self.value_hashes(node, True), self.public_hash_value(node),
                self.value_collections(node), (selector,) if known else (), self.value_methods(node))
        if statement and self.exception_entries:
            self.record_exception_entry(self.comparison_state())
        return result

    def restore_comparison_state(self, state):
        (self.sensitive_names, self.unkeyed_hash_names,
         self.explained_names, self.sensitive_containers) = map(set, state[:4])
        (self.hash_objects, self.hash_elements,
         self.hash_collections, self.scalar_names, self.bound_methods, self.collection_heap) = map(dict, state[4:])

    def join_comparison_states(self, *states):
        # Sensitive provenance may come from any path. A public explanation
        # or unkeyed-hash role must instead hold on every incoming path.
        self.sensitive_names = set.union(*(state[0] for state in states))
        self.unkeyed_hash_names = set.intersection(*(state[1] for state in states))
        self.explained_names = set.intersection(*(state[2] for state in states))
        self.sensitive_containers = set.union(*(state[3] for state in states))
        self.hash_objects = self.merge_hash_bindings(*(state[4] for state in states))
        self.hash_elements = self.merge_hash_bindings(*(state[5] for state in states))
        self.hash_collections = self.merge_hash_bindings(*(state[6] for state in states))
        self.scalar_names = self.merge_scalar_bindings(*(state[7] for state in states))
        self.bound_methods = self.merge_hash_bindings(*(state[8] for state in states))
        self.collection_heap = self.merge_collection_heaps(*(state[9] for state in states))

    def sequence_values(self, collections):
        if len(collections) != 1:
            return None
        shape = self.collection_heap.get(next(iter(collections)))
        if shape is None or shape.kind not in {'list', 'tuple'} or shape.length is None:
            return None
        return [self.selected_references(shape, True, index) for index in range(shape.length)]

    def visit_sequence(self, node):
        slots, unknown, length = {}, HashReferences(), 0
        for item in node.elts:
            self.visit(item)
            if isinstance(item, ast.Starred):
                values = self.sequence_values(self.value_collections(item.value))
                if values is None:
                    unknown = self.merge_references(
                        unknown, self.collection_references(self.value_collections(item.value), iteration=True))
                    length = None
                    continue
            else:
                values = [self.value_references(item)]
            for value in values:
                if length is None:
                    unknown = self.merge_references(unknown, value)
                else:
                    slots[length] = value
                    length += 1
        self.collection_heap[node] = HashCollection(
            'tuple' if isinstance(node, ast.Tuple) else 'list', tuple(slots.items()), unknown, length)

    def visit_List(self, node):
        self.visit_sequence(node)

    def visit_Tuple(self, node):
        self.visit_sequence(node)

    def merge_mapping_entries(self, shape, entries, unknown=HashReferences(), *, weak=False):
        slots = dict(shape.slots)
        present = set(shape.present)
        if unknown != HashReferences():
            slots = {key: self.merge_references(value, unknown) for key, value in slots.items()}
        for key, value in entries:
            slots[key] = self.merge_references(slots.get(key, shape.unknown), value) if weak else value
            if not weak:
                present.add(key)
        return shape._replace(slots=tuple(slots.items()), unknown=self.merge_references(shape.unknown, unknown),
                              present=frozenset(present))

    def mapping_update(self, shape, value, *, weak=False):
        collections = self.value_collections(value)
        incoming = [self.collection_heap[identity] for identity in collections
                    if identity in self.collection_heap and self.collection_heap[identity].kind == 'dict']
        if not incoming:
            rows = self.sequence_values(collections)
            if rows is not None:
                for row in rows:
                    pair = self.sequence_values(row.collections)
                    if pair is None or len(pair) != 2:
                        break
                    if pair[0].selector:
                        shape = self.merge_mapping_entries(shape, ((pair[0].selector[0], pair[1]),), weak=weak)
                    else:
                        shape = self.merge_mapping_entries(shape, (), pair[1])
            # Unknown input can replace any existing entry, but cannot prove
            # the old reference absent. Preserve only may-alias information.
            return shape
        for candidate in incoming:
            shape = self.merge_mapping_entries(shape, tuple((key, value) for key, value in candidate.slots
                                                           if key in candidate.present), candidate.unknown,
                                               weak=weak or len(incoming) != 1)
            shape = self.merge_mapping_entries(shape, tuple((key, value) for key, value in candidate.slots
                                                           if key not in candidate.present), weak=True)
        return shape

    def visit_Dict(self, node):
        shape = HashCollection('dict', ())
        for key, value in zip(node.keys, node.values):
            # Dict displays evaluate each key immediately before its value;
            # the generic AST order visits every key before any of the values.
            if key is not None:
                self.visit(key)
            self.visit(value)
            if key is None:
                shape = self.mapping_update(shape, value)
                continue
            known, selected = self.collection_key(key)
            references = self.value_references(value)
            shape = self.merge_mapping_entries(shape, ((selected, references),) if known else (),
                                               HashReferences() if known else references)
            shape = shape._replace(keys=self.merge_references(shape.keys, self.value_references(key)))
        self.collection_heap[node] = shape

    def visit_Subscript(self, node):
        self.visit(node.value)
        self.visit(node.slice)
        if isinstance(node.slice, ast.Slice) and isinstance(node.ctx, ast.Load):
            collections = self.value_collections(node.value)
            values = self.sequence_values(collections)
            bounds = [self.collection_key(value) if value is not None else (True, None)
                      for value in (node.slice.lower, node.slice.upper, node.slice.step)]
            if values is not None and all(known and (bound is None or isinstance(bound, int))
                                          for known, bound in bounds) and bounds[2][1] != 0:
                selected = values[slice(*(bound for _known, bound in bounds))]
                shape = self.collection_heap[next(iter(collections))]
                self.collection_heap[node] = HashCollection(shape.kind, tuple(enumerate(selected)),
                                                             length=len(selected))
            elif collections:
                self.collection_heap[node] = HashCollection(
                    'list', (), self.collection_references(collections, iteration=True))

    def store_collection_slot(self, target, references, *, delete=False, collections=None, weak=False):
        if collections is None:
            collections = self.value_collections(target.value)
        known, key = self.collection_key(target.slice)
        for identity in collections:
            shape = self.collection_heap.get(identity)
            if shape is None or shape.kind not in {'list', 'dict'}:
                continue
            selected, certain = key, known
            if shape.kind == 'list' and certain:
                if not isinstance(selected, int):
                    continue
                if selected < 0:
                    if shape.length is None:
                        certain = False
                    else:
                        selected += shape.length
                if certain and shape.length is not None and not 0 <= selected < shape.length:
                    continue
            slots = dict(shape.slots)
            if isinstance(target.slice, ast.Slice):
                # Slice stores can insert and shift references; without an
                # exact size, subsequent indices may select any old/new item.
                all_values = self.merge_references(self.collection_references((identity,)), references)
                updated = HashCollection(shape.kind, (), all_values, keys=shape.keys)
            elif certain:
                if delete and shape.kind == 'list' and shape.length is not None:
                    values = [slots.get(index, shape.unknown) for index in range(shape.length)
                              if index != selected]
                    updated = shape._replace(slots=tuple(enumerate(values)), length=len(values))
                else:
                    # An empty dict entry records definite absence even when
                    # a prior unknown-key write could have used the same key.
                    slots[selected] = HashReferences() if delete else references
                    present = shape.present - {selected} if delete else shape.present | {selected}
                    updated = shape._replace(slots=tuple(slots.items()), present=frozenset(present))
            elif delete:
                updated = HashCollection(shape.kind, (), self.collection_references((identity,)), keys=shape.keys)
            else:
                updated = self.merge_mapping_entries(shape, (), references)
            if weak or len(collections) != 1:
                updated = self.merge_collection_heaps({identity: shape}, {identity: updated})[identity]
            self.collection_heap[identity] = updated

    def collection_call(self, node):
        methods = self.value_methods(node.func)
        for method in methods:
            self.apply_collection_method(node, method, weak=len(methods) != 1)

    def apply_collection_method(self, node, binding, *, weak=False):
        collections = binding.receiver.collections
        method = binding.name
        if method in {'__setitem__', '__delitem__'} and not node.keywords:
            if len(node.args) == (2 if method == '__setitem__' else 1):
                target = ast.Subscript(value=node.func, slice=node.args[0], ctx=ast.Store())
                self.store_collection_slot(target, self.value_references(node.args[1])
                                           if method == '__setitem__' else HashReferences(),
                                           delete=method == '__delitem__', collections=collections, weak=weak)
            return
        returned = []
        copies = []
        for identity in collections:
            shape = self.collection_heap.get(identity)
            if shape is None:
                continue
            updated = shape
            values = self.sequence_values(frozenset((identity,)))
            if method == 'copy' and not node.args and not node.keywords:
                copies.append(shape)
            elif method == 'clear' and not node.args and not node.keywords and shape.kind in {'list', 'dict'}:
                updated = HashCollection(shape.kind, (), length=0 if shape.kind == 'list' else None)
            elif shape.kind == 'dict' and method == 'update' and len(node.args) <= 1:
                if node.args:
                    updated = self.mapping_update(updated, node.args[0])
                for keyword in node.keywords:
                    if keyword.arg is None:
                        updated = self.mapping_update(updated, keyword.value)
                    else:
                        updated = self.merge_mapping_entries(updated, ((keyword.arg, self.value_references(keyword.value)),))
            elif shape.kind == 'dict' and method in {'get', 'pop', 'setdefault'} and 1 <= len(node.args) <= 2 and not node.keywords:
                known, key = self.collection_key(node.args[0])
                selected = self.selected_references(shape, known, key)
                slots = dict(shape.slots)
                if method in {'get', 'setdefault'}:
                    default = self.value_references(node.args[1]) if len(node.args) == 2 else HashReferences()
                    selected = (selected if known and key in shape.present
                                else self.merge_references(selected, default))
                    if method == 'setdefault':
                        updated = self.merge_mapping_entries(shape, ((key, selected),) if known else (),
                                                             HashReferences() if known else default)
                elif known:
                    if key not in shape.present and len(node.args) == 2:
                        selected = self.merge_references(selected, self.value_references(node.args[1]))
                    slots[key] = HashReferences()
                    updated = shape._replace(slots=tuple(slots.items()), present=shape.present - {key})
                else:
                    if len(node.args) == 2:
                        selected = self.merge_references(selected, self.value_references(node.args[1]))
                    updated = shape._replace(present=frozenset())
                returned.append(selected)
            elif shape.kind == 'list' and not node.keywords:
                if method in {'append', 'extend'} and len(node.args) == 1:
                    extra = ([self.value_references(node.args[0])] if method == 'append'
                             else self.sequence_values(self.value_collections(node.args[0])))
                    if values is not None and extra is not None and not self.repeated_evaluation:
                        updated = HashCollection('list', tuple(enumerate(values + extra)), length=len(values) + len(extra))
                    else:
                        additions = (self.merge_references(*extra) if extra is not None else
                                     self.collection_references(self.value_collections(node.args[0]), iteration=True))
                        updated = shape._replace(unknown=self.merge_references(shape.unknown, additions), length=None)
                elif method == 'insert' and len(node.args) == 2:
                    known, index = self.collection_key(node.args[0])
                    item = self.value_references(node.args[1])
                    if values is not None and known and isinstance(index, int) and not self.repeated_evaluation:
                        values.insert(index, item)
                        updated = HashCollection('list', tuple(enumerate(values)), length=len(values))
                    else:
                        updated = HashCollection('list', (), self.merge_references(
                            self.collection_references((identity,)), item))
                elif method == 'pop' and len(node.args) <= 1:
                    known, index = self.collection_key(node.args[0]) if node.args else (True, -1)
                    returned.append(self.selected_references(shape, known, index))
                    if values is not None and known and isinstance(index, int) and -len(values) <= index < len(values):
                        values.pop(index)
                        updated = HashCollection('list', tuple(enumerate(values)), length=len(values))
                    else:
                        updated = HashCollection('list', (), self.collection_references((identity,)))
                elif method == 'reverse' and not node.args:
                    if values is not None:
                        updated = HashCollection('list', tuple(enumerate(reversed(values))), length=len(values))
                    else:
                        updated = HashCollection('list', (), self.collection_references((identity,)))
            if weak or len(collections) != 1:
                updated = self.merge_collection_heaps({identity: shape}, {identity: updated})[identity]
            self.collection_heap[identity] = updated
        if copies:
            if node in self.call_references and node in self.collection_heap:
                copies.append(self.collection_heap[node])
            self.collection_heap[node] = self.merge_collection_heaps(*({node: shape} for shape in copies))[node]
            returned.append(HashReferences(collections=frozenset((node,))))
        if returned:
            if node in self.call_references:
                returned.append(self.call_references[node])
            self.call_references[node] = self.merge_references(*returned)

    def visit_If(self, node):
        self.visit(node.test)
        before = self.comparison_state()
        for statement in node.body:
            self.visit(statement)
        body = self.comparison_state()
        self.restore_comparison_state(before)
        for statement in node.orelse:
            self.visit(statement)
        self.join_comparison_states(body, self.comparison_state())

    def bind_iteration_target(self, target, values, source=None, iterable=None):
        """Assign possible elements, preserving literal unpacking positions.

        Iteration overwrites its target before the body executes. A secret
        elsewhere in a literal row does not make its public label sensitive;
        an unresolved iterable instead retains conservative aggregate facts.
        """
        if source is None:
            source = self.comparison_state()
        if isinstance(target, (ast.Tuple, ast.List)):
            stars = [index for index, child in enumerate(target.elts) if isinstance(child, ast.Starred)]
            positioned = values and len(stars) <= 1 and all(
                isinstance(value, (ast.Tuple, ast.List))
                and (len(value.elts) >= len(target.elts) - 1 if stars
                     else len(value.elts) == len(target.elts))
                and not any(isinstance(item, ast.Starred) for item in value.elts)
                for value in values
            )
            for index, child in enumerate(target.elts):
                selected = values
                if positioned:
                    if isinstance(child, ast.Starred):
                        tail = len(target.elts) - index - 1
                        selected = [ast.List(elts=value.elts[index:len(value.elts) - tail], ctx=ast.Load())
                                    for value in values]
                    else:
                        selected = [value.elts[len(value.elts) - len(target.elts) + index]
                                    if stars and index > stars[0] else value.elts[index] for value in values]
                self.bind_iteration_target(child, selected, source, iterable)
        elif isinstance(target, ast.Starred):
            self.bind_iteration_target(target.value, values, source, iterable)
        elif isinstance(target, ast.Name):
            before = self.comparison_state()
            completed = []
            for value in values or [ast.Constant(value=None)]:
                self.restore_comparison_state(source)
                if isinstance(value, ast.Name) and value.id == target.id:
                    # Keep the captured value's same-name provenance, but do
                    # not revive a public-hash proof lost through mutation.
                    if target.id not in before[1]:
                        self.unkeyed_hash_names.discard(target.id)
                else:
                    self.mark_assignment([target.id], value)
                if value is iterable:
                    if self.expr_is_sensitive(value) or self.expr_has_sensitive_container(value):
                        self.sensitive_names.add(target.id)
                    collections = self.value_collections(value)
                    if collections:
                        elements = self.collection_references(collections, iteration=True)
                        self.hash_objects[target.id] = elements.objects
                        self.hash_collections[target.id] = elements.collections
                        self.hash_elements[target.id] = self.contained_hashes(elements.collections)
                        self.bound_methods[target.id] = elements.methods
                    else:
                        self.hash_objects[target.id] = self.value_hashes(value, True)
                        self.hash_collections[target.id] = frozenset()
                        self.bound_methods[target.id] = frozenset()
                    self.scalar_names[target.id] = ()
                completed.append(self.comparison_state())
            self.join_comparison_states(*completed)
            assigned = self.comparison_state()
            facts = [target.id in names for names in assigned[:4]]
            self.restore_comparison_state(before)
            for names, present in zip((self.sensitive_names, self.unkeyed_hash_names,
                                       self.explained_names, self.sensitive_containers), facts):
                (names.add if present else names.discard)(target.id)
            self.hash_objects[target.id] = assigned[4].get(target.id, frozenset())
            self.hash_elements[target.id] = assigned[5].get(target.id, frozenset())
            self.hash_collections[target.id] = assigned[6].get(target.id, frozenset())
            self.scalar_names[target.id] = assigned[7].get(target.id, ())
            self.bound_methods[target.id] = assigned[8].get(target.id, frozenset())
        else:
            # Attribute/subscript targets can execute their own comparisons.
            self.visit(target)

    def iteration_values(self, iterable):
        if isinstance(iterable, ast.Dict) and all(key is not None for key in iterable.keys):
            return iterable.keys
        if isinstance(iterable, (ast.List, ast.Tuple, ast.Set)):
            return iterable.elts
        return [iterable]

    def visit_loop(self, node, condition):
        self.visit(condition)
        before = self.comparison_state()
        head = before
        self.repeated_evaluation += 1
        while True:
            self.restore_comparison_state(head)
            if isinstance(node, ast.While):
                self.visit(condition)
            else:
                # The iterable expression is evaluated once, before any
                # target writes or backedges can rebind its source names.
                self.bind_iteration_target(node.target, self.iteration_values(condition), before, condition)
            for statement in node.body:
                self.visit(statement)
            # This join is monotone over the finite set of local name facts:
            # a backedge can add sensitivity or remove a public explanation.
            self.join_comparison_states(head, self.comparison_state())
            updated = self.comparison_state()
            if updated == head:
                break
            head = updated
        self.repeated_evaluation -= 1
        for statement in node.orelse:
            self.visit(statement)
        self.join_comparison_states(before, head, self.comparison_state())

    def visit_For(self, node):
        self.visit_loop(node, node.iter)

    def visit_AsyncFor(self, node):
        self.visit_For(node)

    def visit_While(self, node):
        self.visit_loop(node, node.test)

    def visit_comprehension(self, node):
        # Only the first iterable belongs to the surrounding lexical scope.
        # Its value must be captured before any target is overwritten.
        self.visit(node.generators[0].iter)
        names = {name for generator in node.generators for name in target_names(generator.target)}
        scope = ComparisonScope(names, self.comparison_state(), set())
        self.expression_scopes.append(scope)
        self.repeated_evaluation += 1
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
            self.bind_iteration_target(generator.target, self.iteration_values(generator.iter),
                                       iterable=generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        values = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
        for value in values:
            self.visit(value)
        self.comprehension_values[node] = ComparisonValue(
            any(self.expr_is_sensitive(value) for value in values), True, frozenset(),
            frozenset().union(*(self.value_hashes(value) | self.value_hashes(value, True) for value in values)))
        if not isinstance(node, ast.GeneratorExp):
            value = node.value if isinstance(node, ast.DictComp) else node.elt
            self.collection_heap[node] = HashCollection(
                'dict' if isinstance(node, ast.DictComp) else 'list', (), self.value_references(value),
                keys=self.value_references(node.key) if isinstance(node, ast.DictComp) else HashReferences())
        after = self.project_scope(self.comparison_state(), scope)
        self.expression_scopes.pop()
        self.repeated_evaluation -= 1
        # A filter, empty iterable, or deferred generator can leave the outer
        # bindings unchanged. Effects that may happen must still survive.
        self.join_comparison_states(scope.before, after)

    visit_ListComp = visit_comprehension
    visit_SetComp = visit_comprehension
    visit_DictComp = visit_comprehension
    visit_GeneratorExp = visit_comprehension

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self.mark_assignment(target_names(node.target), node.value)
        # This write can precede a failing expression in the same statement.
        # Projection keeps comprehension/lambda locals out of the handler.
        self.record_exception_entry(self.comparison_state())

    def visit_BoolOp(self, node):
        self.visit(node.values[0])
        for value in node.values[1:]:
            before = self.comparison_state()
            self.visit(value)
            self.join_comparison_states(before, self.comparison_state())

    def visit_IfExp(self, node):
        self.visit(node.test)
        before = self.comparison_state()
        self.visit(node.body)
        body = self.comparison_state()
        self.restore_comparison_state(before)
        self.visit(node.orelse)
        self.join_comparison_states(body, self.comparison_state())

    def visit_Lambda(self, node):
        arguments = [*node.args.posonlyargs, *node.args.args]
        defaults = [*node.args.defaults, *(value for value in node.args.kw_defaults if value is not None)]
        for value in defaults:
            self.visit(value)
        parameters = arguments + list(node.args.kwonlyargs)
        parameters += [arg for arg in (node.args.vararg, node.args.kwarg) if arg is not None]
        names = {arg.arg for arg in parameters}
        pending = [node.body]
        while pending:
            child = pending.pop()
            if isinstance(child, ast.Lambda):
                continue
            if isinstance(child, ast.NamedExpr):
                names.update(target_names(child.target))
            pending.extend(ast.iter_child_nodes(child))
        scope = ComparisonScope(names, self.comparison_state(), set())
        self.expression_scopes.append(scope)
        for bindings in (self.sensitive_names, self.unkeyed_hash_names,
                         self.explained_names, self.sensitive_containers):
            bindings.difference_update(names)
        for bindings in (self.hash_objects, self.hash_elements, self.hash_collections,
                         self.scalar_names, self.bound_methods):
            for name in names:
                bindings.pop(name, None)
        self.sensitive_names.update(arg.arg for arg in parameters if name_is_sensitive(arg.arg))
        pairs = list(zip(arguments[len(arguments) - len(node.args.defaults):], node.args.defaults))
        pairs += [(arg, value) for arg, value in zip(node.args.kwonlyargs, node.args.kw_defaults)
                  if value is not None]
        for arg, value in pairs:
            self.mark_assignment([arg.arg], value)
        self.visit(node.body)
        after = self.project_scope(self.comparison_state(), scope)
        self.expression_scopes.pop()
        self.join_comparison_states(scope.before, after)

    def visit_Try(self, node):
        before = self.comparison_state()
        self.exception_entries.append(before)
        for statement in node.body:
            self.visit(statement)
        exceptions = self.exception_entries.pop()
        self.record_exception_entry(exceptions)
        for statement in node.orelse:
            self.visit(statement)
        completed = [self.comparison_state()]
        for handler in node.handlers:
            self.restore_comparison_state(exceptions)
            self.visit(handler)
            completed.append(self.comparison_state())
        self.join_comparison_states(*completed)
        for statement in node.finalbody:
            self.visit(statement)

    def visit_TryStar(self, node):
        self.visit_Try(node)

    def visit_Match(self, node):
        self.visit(node.subject)
        before = self.comparison_state()
        completed = [before]
        for case in node.cases:
            self.restore_comparison_state(before)
            self.visit(case)
            completed.append(self.comparison_state())
        self.join_comparison_states(*completed)

    def visit_FunctionDef(self, node):
        old_sensitive = set(self.sensitive_names)
        old_containers = set(self.sensitive_containers)
        old_hash_objects, old_hash_elements = self.hash_objects, self.hash_elements
        old_collections, old_heap, old_scalars = self.hash_collections, self.collection_heap, self.scalar_names
        old_methods = self.bound_methods
        old_repeated = self.repeated_evaluation
        old_expression_scopes = self.expression_scopes
        self.hash_objects, self.hash_elements = {}, {}
        self.hash_collections, self.collection_heap, self.scalar_names = {}, {}, {}
        self.bound_methods = {}
        self.repeated_evaluation = 0
        self.expression_scopes = []
        old_exceptions = self.exception_entries
        self.exception_entries = []
        old_unkeyed = set(self.unkeyed_hash_names)
        old_explained = set(self.explained_names)
        old_public_signals = self.public_signal_bindings
        self.sensitive_names.clear()
        self.sensitive_containers.clear()
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
        self.sensitive_containers = old_containers
        self.exception_entries = old_exceptions
        self.unkeyed_hash_names = old_unkeyed
        self.explained_names = old_explained
        self.public_signal_bindings = old_public_signals
        self.hash_objects, self.hash_elements = old_hash_objects, old_hash_elements
        self.hash_collections, self.collection_heap, self.scalar_names = old_collections, old_heap, old_scalars
        self.bound_methods = old_methods
        self.repeated_evaluation = old_repeated
        self.expression_scopes = old_expression_scopes

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Module(self, node):
        self.structural_values = StructuralFingerprints(node).public
        self.unkeyed_digest_helpers = local_unkeyed_digest_helpers(node)
        self.generic_visit(node)

    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            self.bind_assignment_target(target, node.value)

    def bind_assignment_target(self, target, value):
        if (isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List))
                and len(target.elts) == len(value.elts)
                and not any(isinstance(item, ast.Starred) for item in (*target.elts, *value.elts))):
            for child, item in zip(target.elts, value.elts):
                self.bind_assignment_target(child, item)
        elif isinstance(target, ast.Subscript):
            self.visit(target)
            self.store_collection_slot(target, self.value_references(value))
        else:
            self.mark_assignment(target_names(target), value)
            self.visit(target)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            self.bind_assignment_target(node.target, node.value)
        else:
            self.visit(node.target)
        self.visit(node.annotation)

    def visit_AugAssign(self, node):
        self.visit(node.target)
        references = self.value_references(node.target)
        selector = self.collection_key(node.target)
        self.visit(node.value)
        method = 'extend' if isinstance(node.op, ast.Add) else 'update' if isinstance(node.op, ast.BitOr) else None
        inplace = bool(method and references.collections)
        if inplace:
            call = ast.Call(func=node.target, args=[node.value], keywords=[])
            self.apply_collection_method(call, CapturedHashMethod(method, references))
        for name in target_names(node.target):
            known, value = self.combine_selectors(node.op, selector, self.collection_key(node.value))
            self.scalar_names[name] = (value,) if known else ()
            if inplace:
                # The left reference is captured before the RHS executes;
                # a walrus rebinding of the destination cannot redirect +=.
                self.hash_objects[name] = references.objects
                self.hash_collections[name] = references.collections
                self.hash_elements[name] = self.contained_hashes(references.collections)
                self.bound_methods[name] = references.methods
        if isinstance(node.target, ast.Subscript):
            self.store_collection_slot(node.target, references if inplace else self.merge_references(
                references, self.value_references(node.value)))

    def visit_Delete(self, node):
        for target in node.targets:
            self.visit(target)
            if isinstance(target, ast.Subscript):
                self.store_collection_slot(target, HashReferences(), delete=True)
            for name in target_names(target):
                for bindings in (self.hash_objects, self.hash_elements, self.hash_collections,
                                 self.scalar_names, self.bound_methods):
                    bindings.pop(name, None)

    def visit_Call(self, node):
        self.visit(node.func)
        for argument in node.args:
            self.visit(argument)
        for keyword in node.keywords:
            self.visit(keyword.value)
        if self.repeated_evaluation and self.is_unkeyed_hash_ctor(node):
            self.repeated_hash_sites.add(node)
        self.collection_call(node)
        # h = hashlib.sha256(); h.update(secret)  -> h is no longer a plain checksum.
        func = node.func
        direct_update = isinstance(func, ast.Attribute) and func.attr == 'update'
        updates = [method.receiver.objects for method in self.value_methods(func) if method.name == 'update']
        if (direct_update or updates) and self.call_input_is_sensitive(node):
            objects = frozenset().union(*updates)
            if direct_update:
                objects |= self.value_hashes(func.value)
            repeated = objects & self.repeated_hash_sites
            direct_name = func.value.id if direct_update and isinstance(func.value, ast.Name) else None
            uncertain = {name for name in self.unkeyed_hash_names if name != direct_name
                         and self.hash_objects.get(name, frozenset()) & repeated}
            for scope in self.expression_scopes:
                uncertain.update(name for name in scope.before[1]
                                 if (name != direct_name or name in scope.names)
                                 and scope.before[4].get(name, frozenset()) & repeated)
            if uncertain:
                self.incomplete_reasons.add(
                    f'line {node.lineno}: hash mutation through a repeated allocation site '
                    'needs per-instance collection identity; analysis is incomplete')
            # Repeated sites stand for several runtime instances. They may
            # invalidate a different constructor binding, but cannot establish
            # which instance changed. Preserve independent findings and report
            # that boundary instead of manufacturing a secret-comparison alert.
            objects -= repeated
            for scope in self.expression_scopes:
                scope.mutations.update(objects)
            self.unkeyed_hash_names.difference_update(
                name for name, aliases in self.hash_objects.items() if objects & aliases)
            if direct_update and isinstance(func.value, ast.Name):
                self.unkeyed_hash_names.discard(func.value.id)

    def visit_Compare(self, node):
        self.visit(node.left)
        values = [node.left] + list(node.comparators)
        for index, (left, operator, right) in enumerate(zip(values, node.ops, values[1:])):
            before = self.comparison_state()
            self.visit(right)
            if index:
                self.join_comparison_states(before, self.comparison_state())
            if not isinstance(operator, (ast.Eq, ast.NotEq)):
                continue
            # Adjacent pairs own their evidence: a numeric neighbor must not
            # hide a later credential comparison in the same Python chain.
            scalar_literal = any(
                isinstance(value, ast.Constant) and not isinstance(value.value, (str, bytes))
                for value in (left, right)
            )
            # Keep literal shape-dispatch comparisons quiet, but a tuple
            # explicitly containing secret material still leaks by equality.
            public_display = (
                any(is_constant_display(value) for value in (left, right))
                and not any(self.expr_has_sensitive_container(value) for value in (left, right))
            )
            if not (scalar_literal or public_display) and any(self.expr_is_sensitive(value) for value in (left, right)):
                self.remember_issue(node.lineno)

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
    analyzer.require_complete()


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
    failures = []
    for file_path in iter_files(ROOT):
        try:
            analyze(file_path, issues)
        except AnalysisLimit as exc:
            failures.append(f'{file_path}: {exc}')
    if not failures:
        print(f'__COUNT__\t{len(issues)}')
    for file_name, line_no, code in issues[:25]:
        print(f'__SAMPLE__\t{file_name}\t{line_no}\t{code}')
    for failure in failures:
        print(failure, file=sys.stderr)
    return 2 if failures else 0


_SEVERITY = "critical"
_MESSAGE = (
    "Secret, signature, or token compared with ==/!=; "
    "use hmac.compare_digest() or secrets.compare_digest()"
)


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    failures = []
    for path in ctx.files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        issues: list[tuple[str, int, str]] = []
        try:
            analyze(path, issues)
        except AnalysisLimit as exc:
            failures.append(f'{path}: {exc}')
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
    if failures:
        raise AnalysisLimit('; '.join(failures))


def _scan_code(code: str) -> list[tuple[str, int, str]]:
    lines = code.splitlines()
    visitor = ConstantTimeCompareAnalyzer(Path("memory.py"), lines)
    visitor.visit(ast.parse(code))
    visitor.require_complete()
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
    # Wrapping a signature in a tuple still compares that secret element.
    assert lines == [4, 6, 9, 11], lines


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
