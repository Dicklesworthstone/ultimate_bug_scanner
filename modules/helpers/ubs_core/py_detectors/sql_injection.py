"""ubs_core.py_detectors.sql_injection — category 7 interpolated SQL, two-tier (GH #94).

Port of run_sql_injection_checks (modules/ubs-python.sh 973-1386): an
ast.NodeVisitor that flags f-string / format() / % / concatenation SQL reaching
execute-style sinks (execute, executemany, executescript, raw, read_sql,
read_sql_query, scalar, scalars, and Django .extra(where=...)).

GH #94 provenance tiers: an interpolated SQL string is CRITICAL only when at
least one interpolated value can carry external data (calls, attributes,
subscripts, awaits, function parameters, or names bound to such values —
including names bound to other interpolated SQL); provably compile-time
constant interpolants are as safe as a literal and produce no finding; plain
names of unknown origin (e.g. imported constants) surface as WARNING.
Module-constant f-strings therefore stay silent (static tier).

Statement-owned `ubs:ignore` comments suppress the emitted SQL tier's rule ID.

Statement templates, raw predicates and SELECT mapping values retain distinct
facts through the existing bounded flow engine. Finite literal iterables keep
their exact trip counts; finally transforms abrupt as well as normal exits.
Exception matching and unknown callee/heap effects remain conservative. An
exhausted budget or unsupported exception-group flow is not a clean result.
Configured validator contracts are trusted only at binding-resolved calls and
successful execution points. Their proofs are intersected at joins, revoked on
replacement or possible attribute mutation, and scoped to the evaluated value.
"""
from __future__ import annotations

import ast
import os
import re
import tokenize
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.io import python_source_segment
from ubs_core.suppression import SuppressionIndex, build_index, may_have_markers

RULES = (
    ("py.security.sql-injection", 7,
     "Interpolated SQL reaches execution sink",
     "critical",
     "Use parameterized queries, SQLAlchemy bind parameters, or ORM bindings "
     "instead of f-strings, format(), %, or string concatenation"),
    ("py.security.sql-injection-unproven", 7,
     "Interpolated SQL with unproven-static values reaches execution sink",
     "warning",
     "No external data source detected for the interpolated values; still "
     "prefer parameterized queries, or add 'ubs:ignore' if the values are "
     "known constants"),
)

RULE_CRITICAL, RULE_WARNING = RULES[0][0], RULES[1][0]

SQL_RE = re.compile(r'\b(?:select|insert|update|delete|with|merge|call|exec|create|drop|alter|truncate)\b', re.IGNORECASE)
EXECUTE_METHODS = {'execute', 'executemany', 'executescript', 'exec_driver_sql', 'raw', 'read_sql', 'read_sql_query', 'scalar', 'scalars'}
# Bind the SQL slot, never params/parameters: bound values may themselves
# contain SQL-looking text without becoming executable SQL. These are the
# public Psycopg, SQLAlchemy, pandas and Django argument names. SQLite's
# executescript SQL argument is positional-only.
SQL_ARGUMENT_KEYWORDS = {
    'execute': frozenset({'query', 'statement'}),
    'executemany': frozenset({'query'}),
    'exec_driver_sql': frozenset({'statement'}),
    'raw': frozenset({'raw_query'}),
    'read_sql': frozenset({'sql'}),
    'read_sql_query': frozenset({'sql'}),
    'scalar': frozenset({'statement'}),
    'scalars': frozenset({'statement'}),
}

# GH #133: functions a project declares as SQL-identifier sanitizers.
#
# An identifier (schema, table, column) cannot be sent as a bind parameter, so
# code targeting a runtime-configured table has to interpolate it; the accepted
# pattern is to validate against a strict allowlist and quote the result. The
# provenance tiers cannot express that, because `config.pg_table` is an
# ast.Attribute and therefore tainted no matter what ran before it.
#
# Empty by default, so a project that sets nothing keeps today's behaviour
# byte for byte. This is read from the environment rather than a config file
# because ubs has no project config format; a pre-push gate exports it the way
# it already exports UBS_SKIP_CATEGORIES.
SANITIZER_ENV = 'UBS_PY_SQL_SANITIZERS'


def dotted_suffixes(name):
    """Every dotted suffix of `name`, longest first (`a.b.c`, `b.c`, `c`)."""
    parts = name.split('.')
    return {'.'.join(parts[index:]) for index in range(len(parts))}


def configured_sanitizer_targets(environ=None):
    """Exact project-declared targets, before building the spelling index."""
    raw = (environ if environ is not None else os.environ).get(SANITIZER_ENV, '')
    return frozenset(item.strip() for item in raw.split(',') if item.strip())


def configured_sanitizers(environ=None):
    """Sanitizer names from the environment, expanded to their suffixes.

    A project writing `psycopg.sql.Identifier` means the same function that
    the code calls as `sql.Identifier(...)` after `from psycopg import sql`,
    so the spelling index includes suffixes. A suffix alone never authorizes
    a call: SanitizerBindings also verifies its canonical target and scope.
    """
    names = set()
    for item in configured_sanitizer_targets(environ):
        names.update(dotted_suffixes(item))
    return frozenset(names)


def is_sanitizer_call(node, sanitizers, bindings=None):
    """Whether `node` is a call to one of the configured sanitizers."""
    if not sanitizers or not isinstance(node, ast.Call):
        return False
    if bindings is not None:
        return bindings.is_sanitizer(node)
    # Missing scope information is not permission to trust a name match.
    return False


class SanitizerBindings:
    """Resolve selected stable imports and same-file helper definitions.

    Parameters, reassigned names, unknown receivers, decorators, namespace
    escapes and member writes cannot inherit a trusted leaf spelling. This
    intentionally does not infer arbitrary dynamic dispatch or monkeypatches.
    """

    def __init__(self, tree, targets, budget):
        self.targets = targets
        self.budget = budget
        self.scope_of = {}
        self.owner_scopes = {}
        self.member_writes = set()
        self.indirect_rebindings = set()
        self.calls = []
        self.escaped_imports = set()
        self.dynamic_namespace = False
        self._walk(tree, self._scope(tree, None))
        for call in self.calls:
            if isinstance(call.func, ast.Name) and call.func.id in {'exec', 'eval', 'globals', 'locals'}:
                self.dynamic_namespace = True
            for argument in [*call.args, *(kw.value for kw in call.keywords)]:
                resolved = self.resolve(argument)
                if resolved and resolved[0] == 'import':
                    self.escaped_imports.add(resolved[1])

    def _scope(self, node, parent):
        scope = {'node': node, 'parent': parent, 'names': {}}
        self.owner_scopes[node] = scope
        return scope

    @staticmethod
    def _bind(scope, name, value):
        scope['names'].setdefault(name, []).append(value)

    def _walk(self, node, scope):
        self.budget[0] -= 1
        if self.budget[0] < 0:
            raise SQLFlowLimit('SQL binding budget exceeded; analysis is incomplete')
        self.scope_of[node] = scope
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if not isinstance(node, ast.Lambda):
                self._bind(scope, node.name, ('function', node, False))
                for expression in [*node.decorator_list, *([node.returns] if node.returns else [])]:
                    self._walk(expression, scope)
            for expression in [*node.args.defaults, *(v for v in node.args.kw_defaults if v is not None)]:
                self._walk(expression, scope)
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            arguments += [arg for arg in (node.args.vararg, node.args.kwarg) if arg is not None]
            for argument in arguments:
                if argument.annotation is not None:
                    self._walk(argument.annotation, scope)
            inner = self._scope(node, scope)
            for parameter in getattr(node, 'type_params', []):
                self._bind(inner, parameter.name, None)
            positional = _positional_parameters(node)
            decorators = [call_name(d) for d in getattr(node, 'decorator_list', [])]
            for name in _all_parameters(node):
                receiver = None
                if (isinstance(scope['node'], ast.ClassDef) and positional and name == positional[0]
                        and decorators in ([], ['classmethod'])):
                    receiver = ('receiver', scope['node'], not decorators)
                self._bind(inner, name, receiver)
            for statement in ([node.body] if isinstance(node, ast.Lambda) else node.body):
                self._walk(statement, inner)
            return
        if isinstance(node, ast.ClassDef):
            self._bind(scope, node.name, ('class', node, False))
            for expression in [*node.decorator_list, *node.bases, *(kw.value for kw in node.keywords)]:
                self._walk(expression, scope)
            inner = self._scope(node, scope)
            for parameter in getattr(node, 'type_params', []):
                self._bind(inner, parameter.name, None)
            for statement in node.body:
                self._walk(statement, inner)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            self._walk(node.generators[0].iter, scope)
            inner = self._scope(node, scope)
            for index, generator in enumerate(node.generators):
                self._walk(generator.target, inner)
                if index:
                    self._walk(generator.iter, inner)
                for condition in generator.ifs:
                    self._walk(condition, inner)
            for expression in ([node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]):
                self._walk(expression, inner)
            return
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            self.indirect_rebindings.update(node.names)
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, (ast.Name, ast.Attribute)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            self._walk(node.value, scope)
            for target in targets:
                if isinstance(target, ast.Name):
                    self.scope_of[target] = scope
                    self._bind(scope, target.id, ('alias', node.value))
                else:
                    self._walk(target, scope)
            if isinstance(node, ast.AnnAssign):
                self._walk(node.annotation, scope)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            self._bind(scope, node.id, None)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            self.member_writes.add(node.attr)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == '*':
                    self.dynamic_namespace = True
                    continue
                name = alias.asname or alias.name.split('.')[0]
                canonical = alias.name if alias.asname else alias.name.split('.')[0]
                if isinstance(node, ast.ImportFrom):
                    canonical = '.'.join(part for part in (node.module, alias.name) if part)
                    if node.level:
                        canonical = '.' * node.level + canonical
                self._bind(scope, name, ('import', canonical))
        if isinstance(node, ast.ExceptHandler) and node.name:
            self._bind(scope, node.name, None)
        if type(node).__name__ in {'MatchAs', 'MatchStar'} and node.name:
            self._bind(scope, node.name, None)
        if isinstance(node, ast.Call):
            self.calls.append(node)
        if isinstance(node, ast.NamedExpr):
            target_scope = scope
            while isinstance(target_scope['node'], (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                target_scope = target_scope['parent']
            self._walk(node.target, target_scope)
            self._walk(node.value, scope)
            return
        for child in ast.iter_child_nodes(node):
            self._walk(child, scope)

    def lookup(self, name, scope, seen=None):
        if name in self.indirect_rebindings:
            return None
        while scope:
            candidates = scope['names'].get(name)
            if candidates is not None:
                value = candidates[0] if len(candidates) == 1 else None
                if value and value[0] == 'alias':
                    return self.resolve(value[1], seen)
                return value
            child = scope['node']
            scope = scope['parent']
            if not isinstance(child, ast.ClassDef):
                while scope and isinstance(scope['node'], ast.ClassDef):
                    scope = scope['parent']
        return ('unbound', name)

    def resolve(self, node, seen=None):
        self.budget[0] -= 1
        if self.budget[0] < 0:
            raise SQLFlowLimit('SQL binding resolution budget exceeded; analysis is incomplete')
        seen = set() if seen is None else seen
        if node in seen:
            return None
        seen.add(node)
        if isinstance(node, ast.Name):
            return self.lookup(node.id, self.scope_of.get(node), seen)
        if not isinstance(node, ast.Attribute) or node.attr in self.member_writes:
            return None
        parent = self.resolve(node.value, seen)
        if not parent:
            return None
        if parent[0] == 'import':
            return ('import', parent[1] + '.' + node.attr)
        if parent[0] in {'class', 'receiver'}:
            owner = parent[1]
            if owner.decorator_list or owner.bases or owner.keywords:
                return None
            candidates = self.owner_scopes[owner]['names'].get(node.attr, [])
            value = candidates[0] if len(candidates) == 1 else None
            if value and value[0] == 'function':
                method = value[1]
                decorators = [call_name(d) for d in method.decorator_list]
                if decorators not in ([], ['classmethod'], ['staticmethod']):
                    return None
                for decorator in method.decorator_list:
                    if self.resolve(decorator) != ('unbound', call_name(decorator)):
                        return None
                bound = decorators == ['classmethod'] or (not decorators and parent[0] == 'receiver' and parent[2])
                return ('function', method, bound)
        return None

    def eager_function(self, function):
        if isinstance(function, ast.AsyncFunctionDef):
            return False
        return not any(isinstance(node, (ast.Yield, ast.YieldFrom)) and
                       self.scope_of[node]['node'] is function for node in ast.walk(function))

    def is_sanitizer(self, node):
        if self.dynamic_namespace:
            return False
        resolved = self.resolve(node.func)
        if not resolved:
            return False
        if resolved[0] == 'import':
            canonical = resolved[1]
            if any(canonical == root or canonical.startswith(root + '.') for root in self.escaped_imports):
                return False
            if canonical in self.targets:
                return True
        if resolved[0] == 'function':
            if not self.eager_function(resolved[1]) or resolved[1].decorator_list:
                return False
        # A bare project-declared helper is a deliberate contract, not an
        # authorization for every unrelated object's same-named method.
        return (isinstance(node.func, ast.Name) and node.func.id in self.targets
                and resolved[0] in {'unbound', 'import', 'function'})

    def summary(self, node, summaries):
        if self.dynamic_namespace:
            return None
        resolved = self.resolve(node.func)
        if not resolved or resolved[0] != 'function' or not self.eager_function(resolved[1]):
            return None
        function = resolved[1]
        if function.decorator_list and not isinstance(node.func, ast.Attribute):
            return None
        record = summaries.get(function)
        return dict(record, bound_receiver=resolved[2]) if record else None


def rooted_attribute(node):
    """Split an attribute chain into its root name and dotted suffix.

    `config.pg_table` -> `('config', 'pg_table')`; a bare `writeback_column`
    -> `('writeback_column', '')`. Anything not rooted at a plain name — a
    subscript, a call result — returns None, because there is no stable way
    to say which value a caller passed.
    """
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    return current.id, '.'.join(reversed(parts))


def _positional_parameters(func):
    return [arg.arg for arg in list(func.args.posonlyargs) + list(func.args.args)]


def _all_parameters(func):
    args = func.args
    names = set(_positional_parameters(func))
    names.update(arg.arg for arg in args.kwonlyargs)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _bind_call_arguments(node, record):
    """Map parameter name -> caller-side argument expression for one call.

    `cls._validate(config, col)` binds `config`/`col` to the *second* and
    third parameters of a class method. Drop only a receiver proved bound
    by the resolver: Class.instance_method(obj, value) is an unbound call.
    `*args` stops positional binding: past it nothing can be matched to a name.
    """
    positional = list(record['positional'])
    if positional and record.get('bound_receiver', False):
        positional = positional[1:]
    bound = {}
    for index, argument in enumerate(node.args):
        if isinstance(argument, ast.Starred):
            break
        if index < len(positional):
            bound[positional[index]] = argument
    for keyword in node.keywords:
        if keyword.arg:
            bound[keyword.arg] = keyword.value
    return bound


def call_validated_segments(node, text, sanitizers, summaries, stable_arguments=None, bindings=None):
    """Source segments this call validates, direct or through a wrapper.

    A direct sanitizer call validates its own arguments. A call to a function
    whose summary says "my parameter `config` reaches a sanitizer as
    `config.pg_table`" validates the caller's argument extended by that
    suffix — so `cls._validate_writeback_identifiers(config, writeback_column)`
    validates `config.pg_table` and `writeback_column`, and nothing else on
    `config`. That is the difference between a summary and prefix rooting:
    `config.some_other_column` stays tainted (GH #133).
    """
    segments = []
    if is_sanitizer_call(node, sanitizers, bindings):
        for argument in list(node.args) + [keyword.value for keyword in node.keywords]:
            if stable_arguments is not None and argument not in stable_arguments:
                continue
            segment = validation_key(argument)
            if segment:
                segments.append(segment.strip())
        return segments

    name = call_name(node.func)
    if not name:
        return segments
    record = bindings.summary(node, summaries) if bindings is not None else summaries.get(name)
    if not record:
        return segments
    bound = _bind_call_arguments(node, record)
    for parameter, suffixes in record['validates'].items():
        argument = bound.get(parameter)
        if argument is None:
            continue
        if stable_arguments is not None and argument not in stable_arguments:
            continue
        segment = validation_key(argument)
        if not segment:
            continue
        segment = segment.strip()
        for suffix in suffixes:
            segments.append(f'{segment}.{suffix}' if suffix else segment)
    return segments


def validation_key(node):
    """Only stable name/attribute paths can denote a checked binding.

    Repeated calls and subscripts can produce different objects. Source-text
    equality is not evidence that their results are the same checked value.
    """
    rooted = rooted_attribute(node)
    if rooted is None:
        return None
    return '.'.join(part for part in rooted if part)


def _function_validates(func, text, sanitizers, summaries, budget, bindings):
    """Must-validation on every successful helper exit, using the real engine.

    Throwing paths need not validate; caught failures and early returns do.
    A rebinding of a formal parameter never certifies the caller's argument.
    Unresolved aliases are intentionally not exported as validation proof.
    """
    parameters = _all_parameters(func)
    if not parameters:
        return {}
    rebound = set()
    pending = list(func.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            rebound.add(getattr(node, 'name', ''))
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            rebound.add(node.id)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            rebound.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
        if isinstance(node, ast.ExceptHandler) and node.name:
            rebound.add(node.name)
        pending.extend(ast.iter_child_nodes(node))

    analyzer = SQLInjectionAnalyzer(text, text.splitlines(), parameters, {}, sanitizers,
                                    summaries, budget=budget, bindings=bindings)
    analyzer.func_stack.append(func)
    scope = bindings.owner_scopes[func]
    scopes = []
    while scope is not None:
        scopes.append(scope['node'])
        scope = scope['parent']
    analyzer._generator_scope = tuple(reversed(scopes))
    analyzer.value_risks.update({name: 'tainted' for name in parameters})
    flow = analyzer.statements(func.body, analyzer.sql_state())
    successful = [state for kind, state in flow.items() if kind in {'normal', 'return'}]
    if not successful:
        return {}
    proven = set.intersection(*(state[8] for state in successful))
    validates = {}
    for key in proven:
        root, _, suffix = key.partition('.')
        if root in parameters and root not in rebound:
            validates.setdefault(root, set()).add(suffix)
    return validates


def build_sanitizer_summaries(tree, sanitizers, rounds=4, *, text=None, budget=None, bindings=None):
    """Per-definition summaries of parameters validated on successful exits.

    Recomputed a bounded number of times so a wrapper that calls a wrapper is
    reached (`_validate_all` -> `_validate_one` -> `validate_sql_identifier`)
    without letting a recursive definition iterate forever.

    The binding resolver chooses a concrete definition and its receiver.
    Unrelated objects and lexical shadows cannot borrow another definition's
    proof. Unawaited coroutine and unconsumed generator bodies prove nothing.
    """
    summaries = {}
    if not sanitizers:
        return summaries
    if text is None:
        text = ast.unparse(tree)
        tree = ast.parse(text)
    if budget is None:
        budget = [100_000]
    if bindings is None:
        targets = {name for name in sanitizers if not any(
            other.endswith('.' + name) for other in sanitizers)}
        bindings = SanitizerBindings(tree, targets, budget)
    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if not functions:
        return summaries

    for _ in range(rounds):
        current = {}
        for func in functions:
            if not bindings.eager_function(func):
                continue
            validates = _function_validates(func, text, sanitizers, summaries, budget, bindings)
            record = {'positional': _positional_parameters(func), 'validates': validates}
            if validates:
                current[func] = record
        if current == summaries:
            break
        summaries = current
    return summaries


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return ''


def source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


def string_parts(node):
    parts = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            parts.append(child.value)
    return parts


def literal_sql_text(node, text):
    parts = string_parts(node)
    segment = python_source_segment(text, node) or ''
    return ' '.join(parts + [segment])


def looks_like_sql(node, text):
    return bool(SQL_RE.search(literal_sql_text(node, text)))


def all_static_strings(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return all_static_strings(node.left) and all_static_strings(node.right)
    return False


# GH #94 provenance tiers: 'static' = provably compile-time constant,
# 'tainted' = can carry external data (calls, attributes, subscripts, function
# parameters, or names bound to such values), 'unknown' = a plain name whose
# origin is not visible in this file (e.g. an imported constant).
RISK_ORDER = {'static': 0, 'unknown': 1, 'tainted': 2}
SQL_RISK_ORDER = {None: 0, 'warning': 1, 'critical': 2}


class SQLFlowLimit(RuntimeError):
    """The bounded SQL pass could not establish a complete result."""


def max_risk(a, b):
    return a if RISK_ORDER[a] >= RISK_ORDER[b] else b


def join_sql_risks(*risks):
    return max(risks, key=SQL_RISK_ORDER.__getitem__, default=None)


def binding_target_names(target):
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names = []
        for elt in target.elts:
            names.extend(binding_target_names(elt))
        return names
    if isinstance(target, ast.Starred):
        return binding_target_names(target.value)
    return []


def build_provenance(tree):
    """Collect function-parameter names and a per-name provenance risk map
    from every binding in the file (GH #94)."""
    param_names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            for arg in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
                param_names.add(arg.arg)
            if args.vararg:
                param_names.add(args.vararg.arg)
            if args.kwarg:
                param_names.add(args.kwarg.arg)

    bindings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            names = []
            for target in node.targets:
                names.extend(binding_target_names(target))
            if names:
                bindings.append((names, node.value))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            bindings.append(([node.target.id], node.value))
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            bindings.append(([node.target.id], node.value))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            names = binding_target_names(node.target)
            if names:
                bindings.append((names, node.iter))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    names = binding_target_names(item.optional_vars)
                    if names:
                        bindings.append((names, item.context_expr))

    name_risk = {}

    def classify(node):
        if isinstance(node, ast.Constant):
            return 'static'
        if isinstance(node, ast.JoinedStr):
            risk = 'static'
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    risk = max_risk(risk, classify(part.value))
            return risk
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return max_risk(classify(node.left), classify(node.right))
        if isinstance(node, ast.Name):
            if node.id in param_names:
                return 'tainted'
            return name_risk.get(node.id, 'unknown')
        if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript, ast.Await)):
            return 'tainted'
        risk = None
        for child in ast.iter_child_nodes(node):
            child_risk = classify(child)
            risk = child_risk if risk is None else max_risk(risk, child_risk)
        return risk if risk is not None else 'unknown'

    # Fixed-point over name-to-name references (A = "x"; B = A). Each round
    # recomputes every name from its bindings only, so a chain of constants
    # resolves to 'static' regardless of source order; convergence is capped
    # and unresolved names simply stay 'unknown' (surfaced as Warning, never
    # silently dropped).
    for _ in range(4):
        new_risk = {}
        for names, value in bindings:
            risk = classify(value)
            for name in names:
                new_risk[name] = risk if name not in new_risk else max_risk(new_risk[name], risk)
        if new_risk == name_risk:
            break
        name_risk = new_risk
    return param_names, name_risk


class SQLInjectionAnalyzer(ast.NodeVisitor):
    def __init__(self, text, lines, param_names, name_risk, sanitizers=frozenset(), sanitizer_summaries=None,
                 *, max_steps=100_000, budget=None, bindings=None):
        self.text = text
        self.lines = lines
        self.param_names = param_names
        self.name_risk = name_risk
        self.sanitizers = sanitizers
        self.sanitizer_summaries = sanitizer_summaries or {}
        self.bindings = bindings
        self.validated = set()
        # Evaluation-local epochs are not part of the flow lattice. They
        # prevent later argument effects from blessing an earlier argument's
        # now-rebound source expression; no unbounded loop state is added.
        self._binding_epochs = {}
        self._attribute_epoch = 0
        self.func_stack = []
        self.sink_lineno = None
        self.unsafe_sql_vars = set()
        self.weak_sql_vars = set()
        # Raw predicates need no statement keyword. Mapping values remain
        # separate because Django quotes SELECT result-alias keys.
        self.fragment_sql_vars = {}
        self.select_sql_vars = {}
        self.sql_template_vars = set()
        self.value_risks = {}
        self._sink_risks = {}
        self.remaining_steps = max_steps
        self._budget = [max_steps] if budget is None else budget
        self._pending_raise = None
        # A loaded expression denotes its value *at evaluation time*. Later
        # argument/walrus writes must not change a value already captured by
        # a tuple, SQL call or bound format method. AST objects (not their
        # recycled numeric ids) key these bounded per-analysis snapshots.
        self._evaluated_values = {}
        # Generator objects carry identity, not their future yielded value.
        # Aliases share the fresh/exhausted state, including across branches.
        self.generator_bindings = {}
        self.generator_phases = {}
        self._generator_specs = {}
        self._generator_running = set()
        self._generator_scope = ()
        self._builtin_bindings = {}

    def visit(self, node):
        if not isinstance(node, ast.expr):
            return super().visit(node)
        self.step()
        # The same AST may run on another branch, loop iteration or finally
        # exit. Recompute its snapshot instead of reusing a previous store.
        self._evaluated_values.pop(node, None)
        result = super().visit(node)
        if node not in self._evaluated_values:
            self._evaluated_values[node] = self.value_facts(node)
        return result

    @staticmethod
    def join_value_facts(*facts):
        return (join_sql_risks(*(fact[0] for fact in facts)),
                join_sql_risks(*(fact[1] for fact in facts)),
                join_sql_risks(*(fact[2] for fact in facts)),
                any(fact[3] for fact in facts),
                max((fact[4] for fact in facts), key=RISK_ORDER.__getitem__, default='unknown'),
                frozenset().union(*(SQLInjectionAnalyzer.generator_refs(fact) for fact in facts)))

    @staticmethod
    def generator_refs(facts):
        return facts[5] if len(facts) > 5 else frozenset()

    @property
    def issues(self):
        return [(line, code) for risk, line, code in self._sink_risks.values() if risk == 'critical']

    @property
    def warn_issues(self):
        return [(line, code) for risk, line, code in self._sink_risks.values() if risk == 'warning']

    def step(self):
        self._budget[0] -= 1
        self.remaining_steps = self._budget[0]
        if self.remaining_steps < 0:
            raise SQLFlowLimit('SQL dataflow budget exceeded; analysis is incomplete')

    @staticmethod
    def join_sql_states(*states):
        present = [state for state in states if state is not None]
        if not present:
            return None
        unsafe = set().union(*(state[0] for state in present))
        weak = set().union(*(state[1] for state in present)) - unsafe
        fragments, selects = {}, {}
        for state in present:
            for merged, incoming in ((fragments, state[2]), (selects, state[3])):
                for name, risk in incoming.items():
                    merged[name] = join_sql_risks(merged.get(name), risk)
        templates = set().union(*(state[4] for state in present))
        values = {}
        for name in set().union(*(state[5] for state in present)):
            values[name] = max((state[5].get(name, 'unknown') for state in present),
                               key=RISK_ORDER.__getitem__)
        generators = {}
        for name in set().union(*(state[6] for state in present)):
            # A non-generator alternative cannot be silently treated as the
            # known generator from the other arm.
            generators[name] = frozenset().union(*(
                state[6].get(name, frozenset({None})) for state in present))
        phases = {}
        for state in present:
            for identity, incoming in state[7].items():
                phases[identity] = phases.get(identity, frozenset()) | incoming
        # SQL risk is may-flow; validation is must-flow. One bypass or failed
        # validator is enough to revoke a proof at the joined program point.
        validated = set.intersection(*(state[8] for state in present))
        return unsafe, weak, fragments, selects, templates, values, generators, phases, validated

    def merge_flows(self, *flows):
        merged = {}
        for flow in flows:
            for exit_kind, state in flow.items():
                merged[exit_kind] = self.join_sql_states(merged.get(exit_kind), state)
        return merged

    def statements(self, nodes, incoming):
        """Propagate normal execution separately from abrupt control flow.

        None is unreachable, not an empty clean store. Return/break/continue
        cannot run the next statement or accidentally clear another path.
        """
        if incoming is None:
            return {}
        flow = {'normal': incoming}
        for node in nodes:
            state = flow.pop('normal', None)
            if state is None:
                break
            self.step()
            self.restore_sql_state(state)
            enclosing_raise = self._pending_raise
            self._pending_raise = None
            try:
                result = self.visit(node)
                implicit_raise = self._pending_raise
            finally:
                self._pending_raise = enclosing_raise
            if result is None:
                result = {'normal': self.sql_state()}
            if implicit_raise is not None:
                result = self.merge_flows(result, {'raise': implicit_raise})
            flow = self.merge_flows(flow, result)
        return flow

    def visit_Module(self, node):
        self._generator_scope = (node,)
        self.statements(node.body, self.sql_state())

    def builtin_is_unshadowed(self, name):
        """Resolve only an unshadowed builtin, never a look-alike callee.

        A lexical binding anywhere in a function makes that name local even
        before its assignment. Module/class bindings are conservatively
        treated the same way; dynamic rebinding remains unsupported.
        """
        for scope in self._generator_scope:
            if scope not in self._builtin_bindings:
                names = set(_all_parameters(scope)) if hasattr(scope, 'args') else set()
                pending = list(scope.body) if isinstance(scope.body, list) else [scope.body]
                while pending:
                    child = pending.pop()
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        names.add(child.name)
                        continue
                    if isinstance(child, ast.Lambda):
                        continue
                    if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
                        names.add(child.id)
                    if isinstance(child, (ast.Import, ast.ImportFrom)):
                        names.update(alias.asname or alias.name.split('.')[0] for alias in child.names)
                    pending.extend(ast.iter_child_nodes(child))
                self._builtin_bindings[scope] = names
            if name in self._builtin_bindings[scope] or '*' in self._builtin_bindings[scope]:
                return False
        return True

    def visit_FunctionDef(self, node):
        # Defaults/decorators run in the defining scope; the body does not.
        # In particular, a default may execute the *outer* query even when
        # the new function has a parameter with the same name.
        for decorator in node.decorator_list:
            self.visit(decorator)
        self.visit(node.args)
        if node.returns is not None:
            self.visit(node.returns)
        outer = self.sql_state()
        self.validated.clear()
        parameters = _all_parameters(node)
        self.unsafe_sql_vars.difference_update(parameters)
        self.weak_sql_vars.difference_update(parameters)
        self.sql_template_vars.difference_update(parameters)
        for parameter in parameters:
            self.fragment_sql_vars.pop(parameter, None)
            self.select_sql_vars.pop(parameter, None)
            self.generator_bindings.pop(parameter, None)
            self.value_risks[parameter] = 'tainted'
        self.func_stack.append(node)
        scope = self._generator_scope
        self._generator_scope = (*scope, node)
        try:
            self.statements(node.body, self.sql_state())
        finally:
            self.func_stack.pop()
            self._generator_scope = scope
            self.restore_sql_state(outer)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        # Defaults execute now; the deferred body has its own bindings and
        # must not mutate the defining scope or raise into its try block.
        self.visit(node.args)
        outer, enclosing_raise = self.sql_state(), self._pending_raise
        self.validated.clear()
        self.bind_value_facts(_all_parameters(node), (None, None, None, False, 'tainted'))
        self._pending_raise = None
        scope = self._generator_scope
        self._generator_scope = (*scope, node)
        try:
            self.visit(node.body)
        finally:
            self._generator_scope = scope
            self.restore_sql_state(outer)
            self._pending_raise = enclosing_raise
        # Creating a function does not return the value of its deferred body.
        self._evaluated_values[node] = (None, None, None, False, 'unknown')

    def visit_ClassDef(self, node):
        for expression in [*node.decorator_list, *node.bases]:
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)
        outer = self.sql_state()
        scope = self._generator_scope
        self._generator_scope = (*scope, node)
        try:
            body = self.statements(node.body, outer)
        finally:
            self._generator_scope = scope
        self.restore_sql_state(outer)
        # Class-local assignments do not rebind names in the defining scope.
        # Class creation itself can fail through metaclass/decorator code.
        if node.bases or node.keywords or node.decorator_list:
            self.note_possible_raise()
        return {kind: outer for kind in body}

    def sql_state(self):
        """Snapshot SQL-value facts without sharing mutable branch stores."""
        return (self.unsafe_sql_vars.copy(), self.weak_sql_vars.copy(),
                self.fragment_sql_vars.copy(), self.select_sql_vars.copy(),
                self.sql_template_vars.copy(), self.value_risks.copy(),
                self.generator_bindings.copy(), self.generator_phases.copy(), self.validated.copy())

    def restore_sql_state(self, state):
        (self.unsafe_sql_vars, self.weak_sql_vars, self.fragment_sql_vars,
         self.select_sql_vars, self.sql_template_vars, self.value_risks,
         self.generator_bindings, self.generator_phases, self.validated) = (part.copy() for part in state)

    def visit_If(self, node):
        self.visit(node.test)
        incoming = self.sql_state()
        truth = self.literal_truth(node.test)
        if truth is None:
            self.note_possible_raise()
        flow = self.merge_flows(
            self.statements(node.body, incoming) if truth is not False else {},
            self.statements(node.orelse, incoming) if truth is not True else {},
        )
        self.restore_sql_state(flow.get('normal', incoming))
        return flow

    @staticmethod
    def literal_truth(node):
        # Never evaluate source code. Only actual constant AST values have
        # known truth here; arbitrary conditions retain both possibilities.
        return bool(node.value) if isinstance(node, ast.Constant) else None

    def visit_For(self, node):
        if isinstance(node, ast.For) and isinstance(node.iter, (ast.List, ast.Tuple)):
            if not any(isinstance(value, ast.Starred) for value in node.iter.elts):
                items = []
                for value in node.iter.elts:
                    self.visit(value)
                    items.append(self.assignment_bindings(node.target, value))
                return self.finite_loop(node, items)
        self.visit(node.iter)
        if self.generator_refs(self.value_facts(node.iter)):
            raise SQLFlowLimit('SQL generator streaming consumption is unsupported; analysis is incomplete')
        return self.loop(node, self.value_facts(node.iter))

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        return self.loop(node)

    def finite_loop(self, node, items):
        """A literal list/tuple has exactly this many iteration values.

        Evaluate every element before entering the loop. Do not invent a
        second iteration for a singleton or execute an empty literal body.
        Dynamic iterables continue to use the conservative fixed point.
        """
        incoming = current = self.sql_state()
        escaped, breaks = {}, None
        for bindings in items:
            if current is None:
                break
            self.step()
            self.restore_sql_state(current)
            for names, facts in bindings:
                self.bind_value_facts(names, facts)
            body = self.statements(node.body, self.sql_state())
            breaks = self.join_sql_states(breaks, body.get('break'))
            escaped = self.merge_flows(escaped, {
                kind: state for kind, state in body.items() if kind in {'return', 'raise'}
            })
            current = self.join_sql_states(body.get('normal'), body.get('continue'))
        normal = {'normal': breaks} if breaks is not None else {}
        flow = self.merge_flows(escaped, self.statements(node.orelse, current), normal)
        self.restore_sql_state(flow.get('normal', incoming))
        return flow

    def loop(self, node, iterable_facts=None):
        """Finite may-flow fixed point, including zero and later iterations.

        The loop header grows monotonically in the existing SQL-value
        lattice. Break exits bypass else; continue joins the back edge;
        return and raise escape instead of executing following statements.
        For iterables are evaluated once, before any target rebinding.
        """
        incoming = header = self.sql_state()
        escaped = {}
        breaks = None
        while_loop = isinstance(node, ast.While)
        while True:
            self.step()
            self.restore_sql_state(header)
            truth = None
            if while_loop:
                self.visit(node.test)
                truth = self.literal_truth(node.test)
                if truth is None:
                    self.note_possible_raise()
            else:
                # Iterator advancement can fail before the target is bound.
                self.note_possible_raise()
            tested = self.sql_state()
            exhausted = tested if truth is not True else None
            if not while_loop:
                self.bind_value_facts(binding_target_names(node.target), iterable_facts)
            body = self.statements(node.body, self.sql_state()) if truth is not False else {}
            breaks = self.join_sql_states(breaks, body.get('break'))
            escaped = self.merge_flows(escaped, {
                kind: state for kind, state in body.items() if kind in {'return', 'raise'}
            })
            next_header = self.join_sql_states(incoming, body.get('normal'), body.get('continue'))
            if next_header == header:
                break
            header = next_header
        normal = {'normal': breaks} if breaks is not None else {}
        flow = self.merge_flows(escaped, self.statements(node.orelse, exhausted), normal)
        self.restore_sql_state(flow.get('normal', incoming))
        return flow

    def visit_Break(self, node):
        return {'break': self.sql_state()}

    def visit_Continue(self, node):
        return {'continue': self.sql_state()}

    def visit_Return(self, node):
        if node.value is not None:
            self.visit(node.value)
        return {'return': self.sql_state()}

    def visit_Raise(self, node):
        if node.exc is not None:
            self.visit(node.exc)
        if node.cause is not None:
            self.visit(node.cause)
        return {'raise': self.sql_state()}

    def note_possible_raise(self):
        self._pending_raise = self.join_sql_states(self._pending_raise, self.sql_state())

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if isinstance(getattr(node, 'ctx', None), (ast.Store, ast.Del)):
            # Without heap alias proof, a write through any alias can replace
            # a checked property. Never retain a stale attribute validation.
            self.invalidate_attribute_validations()
        self.note_possible_raise()

    visit_Subscript = visit_Attribute
    visit_BinOp = visit_Attribute
    visit_UnaryOp = visit_Attribute
    visit_Compare = visit_Attribute
    visit_Await = visit_Attribute

    def visit_FormattedValue(self, node):
        self.generic_visit(node)
        # Formatting a literal without a format specification cannot invoke
        # user code. Do not fabricate an exception path for f"{7}"; a dynamic
        # value or format specification can fail before an assignment stores.
        if not isinstance(node.value, ast.Constant) or node.format_spec is not None:
            self.note_possible_raise()

    def visit_BoolOp(self, node):
        # Short-circuited operands cannot overwrite the bypass store.
        bypass = None
        values = []
        for index, value in enumerate(node.values):
            self.visit(value)
            if index == len(node.values) - 1:
                values.append(self.value_facts(value))
                break
            truth = self.literal_truth(value)
            if truth is None:
                self.note_possible_raise()
            continuing = True if isinstance(node.op, ast.And) else False
            if truth is not continuing:
                bypass = self.join_sql_states(bypass, self.sql_state())
                values.append(self.value_facts(value))
            if truth is not None and truth is not continuing:
                break
        self.restore_sql_state(self.join_sql_states(bypass, self.sql_state()))
        self._evaluated_values[node] = self.join_value_facts(*values)

    def visit_IfExp(self, node):
        self.visit(node.test)
        incoming, branches = self.sql_state(), []
        values = []
        truth = self.literal_truth(node.test)
        if truth is None:
            self.note_possible_raise()
        for expression, selected in ((node.body, True), (node.orelse, False)):
            if truth is not None and truth is not selected:
                continue
            self.restore_sql_state(incoming)
            self.visit(expression)
            branches.append(self.sql_state())
            values.append(self.value_facts(expression))
        self.restore_sql_state(self.join_sql_states(*branches))
        self._evaluated_values[node] = self.join_value_facts(*values)

    def visit_Dict(self, node):
        # ast.iter_child_nodes lists all keys before all values. Python
        # instead evaluates each key immediately before its associated value.
        for key, value in zip(node.keys, node.values):
            if key is not None:
                self.visit(key)
            self.visit(value)

    @staticmethod
    def restore_local_facts(state, enclosing, names):
        """Remove comprehension locals without undoing outer walrus writes."""
        if state is None:
            return None
        restored = tuple(part.copy() for part in state)
        for index, (part, outer) in enumerate(zip(restored, enclosing)):
            if index == 8:
                part.difference_update(key for key in tuple(part) if key.split('.')[0] in names)
                part.update(key for key in outer if key.split('.')[0] in names)
            elif isinstance(part, set):
                part.difference_update(names)
                part.update(outer.intersection(names))
            else:
                for name in names:
                    if name in outer:
                        part[name] = outer[name]
                    else:
                        part.pop(name, None)
        return restored

    def visit_ListComp(self, node, *, captured=None, consumer_can_raise=False):
        """Evaluate eager comprehensions in loop/filter order and local scope.

        Literal lists/tuples have exact iteration counts. Dynamic iterables
        reuse the finite SQL-state lattice, including zero-trip and backedge
        paths. Only emitted expressions contribute result values; iterables,
        filters and dictionary keys are not SELECT mapping values.
        """
        if len(node.generators) > 64:
            raise SQLFlowLimit('SQL comprehension nesting exceeded; analysis is incomplete')
        first = node.generators[0]
        # Python evaluates just the outermost iterable in the enclosing scope.
        if captured is None:
            self.visit(first.iter)
        else:
            # The outermost iterator was constructed at generator creation.
            # Its expression and element captures must not be evaluated again.
            self._evaluated_values.update(captured)
        enclosing = self.sql_state()
        enclosing_raise = self._pending_raise
        self._pending_raise = None
        local_names = {name for generator in node.generators
                       for name in binding_target_names(generator.target)}
        self.bind_value_facts(local_names, (None, None, None, False, 'unknown'))
        produced = None

        def emit():
            nonlocal produced
            if isinstance(node, ast.DictComp):
                self.visit(node.key)
                key = self.value_facts(node.key)
                self.visit(node.value)
                value = self.value_facts(node.value)
                combined = self.join_value_facts(key, value)
                facts = (combined[0], combined[1], value[1], combined[3], combined[4])
                # Hashing a nonliteral key may raise during insertion.
                if not isinstance(node.key, ast.Constant):
                    self.note_possible_raise()
            else:
                self.visit(node.elt)
                facts = self.value_facts(node.elt)
                if isinstance(node, ast.SetComp) and not isinstance(node.elt, ast.Constant):
                    self.note_possible_raise()
            if consumer_can_raise:
                # A reducer/hash/comparison can fail after this yield while
                # leaving the generator suspended, unlike a body exception
                # which closes it. Preserve that prefix's outer SQL facts.
                phase = self.generator_phases[node]
                self.generator_phases[node] = frozenset({'partial'})
                self.note_possible_raise()
                self.generator_phases[node] = phase
            produced = facts if produced is None else self.join_value_facts(produced, facts)
            return self.sql_state()

        def filtered(index):
            bypass = None
            for condition in node.generators[index].ifs:
                self.visit(condition)
                truth = self.literal_truth(condition)
                if truth is None:
                    self.note_possible_raise()
                if truth is not True:
                    bypass = self.join_sql_states(bypass, self.sql_state())
                if truth is False:
                    return bypass
            result = (level(index + 1, self.sql_state())
                      if index + 1 < len(node.generators) else emit())
            return self.join_sql_states(bypass, result)

        def level(index, incoming):
            self.step()
            self.restore_sql_state(incoming)
            generator = node.generators[index]
            if index:
                self.visit(generator.iter)
            entered = self.sql_state()
            iterable = generator.iter
            if self.generator_refs(self.value_facts(iterable)):
                raise SQLFlowLimit('SQL nested generator iteration is unsupported; analysis is incomplete')
            if (not generator.is_async and isinstance(iterable, (ast.List, ast.Tuple))
                    and not any(isinstance(item, ast.Starred) for item in iterable.elts)):
                # Every iterable element was evaluated before entering its
                # loop, not lazily after earlier body assignments.
                items = [self.assignment_bindings(generator.target, item) for item in iterable.elts]
                current = entered
                for bindings in items:
                    self.step()
                    self.restore_sql_state(current)
                    for names, facts in bindings:
                        self.bind_value_facts(names, facts)
                    current = filtered(index)
                return current
            facts = self.value_facts(iterable)
            header = entered
            while True:
                self.step()
                self.restore_sql_state(header)
                self.note_possible_raise()
                self.bind_value_facts(binding_target_names(generator.target), facts)
                after = filtered(index)
                updated = self.join_sql_states(entered, after)
                if updated == header:
                    return updated
                header = updated

        try:
            result = level(0, self.sql_state())
            self.restore_sql_state(result)
            self._evaluated_values[node] = produced or (None, None, None, False, 'static')
        finally:
            # Iteration variables are local even on exceptional exits; Python
            # assignment-expression targets outside them remain enclosing.
            state = self.restore_local_facts(self.sql_state(), enclosing, local_names)
            raised = self.restore_local_facts(self._pending_raise, enclosing, local_names)
            self.restore_sql_state(state)
            self._pending_raise = self.join_sql_states(enclosing_raise, raised)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp

    def visit_GeneratorExp(self, node):
        """Create a lazy object; only its leftmost iterable executes now."""
        first = node.generators[0].iter
        self.visit(first)
        if not isinstance(first, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            self.note_possible_raise()  # constructing the iterator can fail
        if any(node in refs for refs in self.generator_bindings.values()):
            # Allocation-site reuse must not resurrect an exhausted alias or
            # replace a still-live object's captured iterator with a new one.
            raise SQLFlowLimit('SQL overlapping generator allocations are unsupported; analysis is incomplete')
        captured = {child: self._evaluated_values[child] for child in ast.walk(first)
                    if child in self._evaluated_values}
        asynchronous = any(generator.is_async for generator in node.generators) or any(
            isinstance(child, ast.Await) for expression in
            [node.elt, *(condition for generator in node.generators for condition in generator.ifs)]
            for child in ast.walk(expression))
        self._generator_specs[node] = (self._generator_scope, captured, asynchronous)
        self.generator_phases[node] = frozenset({'fresh'})
        self._evaluated_values[node] = (None, None, None, False, 'unknown', frozenset({node}))

    def materialize_generators(self, references, *, consumer_can_raise=False):
        """Fully consume selected same-scope generators using the eager engine.

        Generator identity and completion are stateful, whereas projected
        SQL values are ordinary captured facts. Do not run an exhausted
        alias again or mistake a generator object's repr for its contents.
        """
        incoming = self.sql_state()
        stores, values = [], []
        for identity in references:
            self.step()
            if identity is None or identity not in self._generator_specs:
                raise SQLFlowLimit('SQL mixed generator binding is unsupported; analysis is incomplete')
            scope, captured, asynchronous = self._generator_specs[identity]
            if scope != self._generator_scope:
                raise SQLFlowLimit('SQL cross-scope generator consumption is unsupported; analysis is incomplete')
            if asynchronous:
                raise SQLFlowLimit('SQL asynchronous generator consumption is unsupported; analysis is incomplete')
            if identity in self._generator_running:
                raise SQLFlowLimit('SQL reentrant generator consumption is unsupported; analysis is incomplete')
            phases = incoming[7].get(identity, frozenset())
            if not phases:
                raise SQLFlowLimit('SQL generator lifetime is unresolved; analysis is incomplete')
            for phase in phases:
                self.restore_sql_state(incoming)
                self.generator_phases[identity] = frozenset({'done'})
                if phase == 'done':
                    values.append((None, None, None, False, 'static'))
                elif phase == 'fresh':
                    self._generator_running.add(identity)
                    try:
                        self.visit_ListComp(identity, captured=captured, consumer_can_raise=consumer_can_raise)
                        value = self.value_facts(identity)
                        if self.generator_refs(value):
                            raise SQLFlowLimit('SQL generator-valued projection is unsupported; analysis is incomplete')
                        values.append(value[:5])
                    finally:
                        self._generator_running.remove(identity)
                        # The AST expression still denotes the generator;
                        # its projected values belong to this consumption.
                        self._evaluated_values[identity] = (
                            None, None, None, False, 'unknown', frozenset({identity}))
                else:
                    raise SQLFlowLimit('SQL partial generator consumption is unsupported; analysis is incomplete')
                stores.append(self.sql_state())
        self.restore_sql_state(self.join_sql_states(*stores))
        return self.join_value_facts(*values)

    def generator_call(self, node):
        """Handle identified full consumers and reject unknown lazy effects."""
        arguments = [(argument, self.generator_refs(self.value_facts(argument))) for argument in node.args]
        arguments += [(keyword.value, self.generator_refs(self.value_facts(keyword.value)))
                      for keyword in node.keywords]
        arguments = [(argument, refs) for argument, refs in arguments if refs]
        receiver = (self.generator_refs(self.value_facts(node.func.value))
                    if isinstance(node.func, ast.Attribute) else frozenset())
        if not arguments and not receiver:
            return False
        if isinstance(node.func, ast.Name) and self.builtin_is_unshadowed(node.func.id):
            name = node.func.id
            if len(node.args) == 1 and not node.keywords and arguments:
                refs = arguments[0][1]
                if name in {'list', 'tuple', 'set', 'frozenset', 'sorted', 'min', 'max', 'sum'}:
                    self._evaluated_values[node] = self.materialize_generators(
                        refs, consumer_can_raise=name not in {'list', 'tuple'})
                    return True
                if name in {'any', 'all'} and all(
                        identity is not None and not self.generator_has_writes_or_sinks(identity) for identity in refs):
                    for identity in refs:
                        self.generator_phases[identity] = frozenset({'partial'})
                    self._evaluated_values[node] = (None, None, None, False, 'static')
                    return True
                if name == 'iter':
                    self._evaluated_values[node] = (None, None, None, False, 'unknown', refs)
                    return True
                if name in {'str', 'repr', 'bool', 'id', 'type'}:
                    # Object introspection does not iterate a generator.
                    self._evaluated_values[node] = (None, None, None, False, 'static')
                    return True
        if receiver and not arguments and not node.args and not node.keywords:
            if node.func.attr == '__iter__':
                self._evaluated_values[node] = (None, None, None, False, 'unknown', receiver)
                return True
            if node.func.attr == 'close':
                for identity in receiver:
                    if identity is None or identity not in self._generator_specs:
                        raise SQLFlowLimit('SQL generator close binding is unresolved; analysis is incomplete')
                    self.generator_phases[identity] = frozenset({'done'})
                self._evaluated_values[node] = (None, None, None, False, 'static')
                return True
        if (isinstance(node.func, ast.Attribute) and node.func.attr == 'join'
                and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)
                and len(node.args) == 1 and not node.keywords and arguments):
            facts = self.materialize_generators(arguments[0][1])
            separator = self.value_facts(node.func.value)
            combined = self.join_value_facts(facts, separator)
            risk = None if combined[4] == 'static' else 'critical' if combined[4] == 'tainted' else 'warning'
            self._evaluated_values[node] = (
                join_sql_risks(combined[0], risk if combined[3] else None),
                join_sql_risks(combined[1], risk), join_sql_risks(combined[2], risk),
                combined[3], combined[4])
            return True
        # These selected APIs consume their input iterables during this call.
        # Their SQL argument was captured earlier; parameter data is not SQL.
        short = call_name(node.func).rsplit('.', 1)[-1]
        consumed = set()
        if short == 'extra':
            consumed.update(argument for argument, context in self.sql_arguments(node) if context == 'fragment')
        elif short == 'executemany':
            if len(node.args) > 1:
                consumed.add(node.args[1])
            consumed.update(keyword.value for keyword in node.keywords if keyword.arg == 'params_seq')
        if not receiver and all(argument in consumed for argument, _ in arguments):
            for argument, refs in arguments:
                self._evaluated_values[argument] = self.materialize_generators(refs)
            return True
        references = receiver | frozenset().union(*(refs for _, refs in arguments))
        if all(identity is not None and not self.generator_has_sql_effects(identity) for identity in references):
            # An opaque consumer of a read-only, non-SQL generator cannot
            # change a tracked SQL binding. Do not turn routine any()/sum()
            # idioms into file-wide failures. Its cursor is now unknown:
            # subsequent modeled consumption must refuse, not restart it.
            for identity in references:
                self.generator_phases[identity] = frozenset({'partial'})
            self._evaluated_values[node] = (None, None, None, False, 'unknown')
            return True
        raise SQLFlowLimit('SQL unknown generator consumer is unsupported; analysis is incomplete')

    def generator_has_sql_effects(self, identity):
        """Conservative relevance test, not a substitute for execution."""
        spec = self._generator_specs.get(identity)
        if spec is None:
            return True
        _, captured, _ = spec
        if any(any(facts[:3]) or self.generator_refs(facts) for facts in captured.values()):
            return True
        deferred = [identity.elt]
        deferred.extend(condition for generator in identity.generators for condition in generator.ifs)
        deferred.extend(generator.iter for generator in identity.generators[1:])
        for expression in deferred:
            if self.sql_risk(expression, require_sql=False):
                return True
        return self.generator_has_writes_or_sinks(identity)

    @staticmethod
    def generator_has_writes_or_sinks(identity):
        deferred = [identity.elt]
        deferred.extend(condition for generator in identity.generators for condition in generator.ifs)
        deferred.extend(generator.iter for generator in identity.generators[1:])
        return any(isinstance(child, ast.NamedExpr) or
                   isinstance(child, ast.Call) and call_name(child.func).rsplit('.', 1)[-1] in EXECUTE_METHODS | {'extra'}
                   for expression in deferred for child in ast.walk(expression))

    def visit_Assert(self, node):
        optimized = self.sql_state()
        self.visit(node.test)
        incoming = self.sql_state()
        truth = self.literal_truth(node.test)
        if truth is not True:
            if node.msg is not None:
                self.visit(node.msg)
            failed = {'raise': self.sql_state()}
        else:
            failed = {}
        # -O removes the entire assert, including side effects in its test.
        # Assertions therefore cannot establish an unconditional clean store
        # or make a later security sink unconditionally unreachable.
        normal = {'normal': self.join_sql_states(optimized, incoming if truth is not False else None)}
        self.restore_sql_state(normal['normal'])
        return self.merge_flows(normal, failed)

    def visit_Try(self, node):
        """Route failures to handlers; resume each pending exit after finally.

        Exception types are not resolved: typed handlers may match, and an
        uncaught path remains possible. A bare handler catches all failures.
        Importantly, else receives only successful body exits, and handler
        failures are not offered to sibling handlers of the same try.
        """
        incoming = self.sql_state()
        body = self.statements(node.body, incoming)
        normal = body.pop('normal', None)
        raised = body.pop('raise', None)
        flow = self.merge_flows(body, self.statements(node.orelse, normal))
        catches_all = False
        if raised is not None:
            for handler in node.handlers:
                self.restore_sql_state(raised)
                if handler.type is not None:
                    self.visit(handler.type)
                if handler.name:
                    self.bind_value_facts([handler.name], (None, None, None, False, 'tainted'))
                handled = self.statements(handler.body, self.sql_state())
                if handler.name:
                    # Python clears the exception target on every exit.
                    for kind, state in handled.items():
                        self.restore_sql_state(state)
                        self.bind_value_facts([handler.name], (None, None, None, False, 'unknown'))
                        handled[kind] = self.sql_state()
                flow = self.merge_flows(flow, handled)
                if handler.type is None:
                    catches_all = True
                    break
            if not catches_all:
                flow = self.merge_flows(flow, {'raise': raised})
        # Failure while evaluating an except type must also run finally.
        # Statement bodies have already returned their own exception stores.
        if self._pending_raise is not None:
            flow = self.merge_flows(flow, {'raise': self._pending_raise})
            self._pending_raise = None
        if node.finalbody:
            finalized = {}
            for exit_kind, state in flow.items():
                final = self.statements(node.finalbody, state)
                resumed = final.pop('normal', None)
                if resumed is not None:
                    finalized = self.merge_flows(finalized, {exit_kind: resumed})
                # A finally return/raise/break/continue replaces that exit.
                finalized = self.merge_flows(finalized, final)
            flow = finalized
        self.restore_sql_state(flow.get('normal', incoming))
        return flow

    def visit_TryStar(self, node):
        # Several except* handlers can execute for one ExceptionGroup;
        # treating them as alternatives would silently discard write effects.
        raise SQLFlowLimit('SQL except* exception-group flow is unsupported; analysis is incomplete')

    def visit_With(self, node):
        incoming = self.sql_state()
        suppressed_setup = None
        for index, item in enumerate(node.items):
            before = self.sql_state()
            self.visit(item.context_expr)
            self.note_possible_raise()
            if index:
                # An already-entered outer manager can suppress failure
                # while evaluating/entering a later manager.
                suppressed_setup = self.join_sql_states(suppressed_setup, before, self.sql_state())
            if item.optional_vars is not None:
                self.bind_value_facts(binding_target_names(item.optional_vars),
                                      (None, None, None, False, 'tainted'))
        flow = self.statements(node.body, self.sql_state())
        normal = self.join_sql_states(flow.get('normal'), flow.get('raise'), suppressed_setup)
        if normal is not None:
            flow['normal'] = normal
        # Unknown __exit__/__aexit__ can suppress exceptions, never returns,
        # breaks or continues. It can also raise from any exiting path.
        for state in flow.values():
            self._pending_raise = self.join_sql_states(self._pending_raise, state)
        self.restore_sql_state(flow.get('normal', incoming))
        return flow

    visit_AsyncWith = visit_With

    def visit_Match(self, node):
        # Each arm has an independent incoming store. Without value/type
        # resolution, refutable patterns may miss; only an unguarded
        # capture/wildcard consumes all remaining subjects.
        self.visit(node.subject)
        incoming = self.sql_state()
        subject_facts = self.value_facts(node.subject)
        flow, exhaustive = {}, False
        for case in node.cases:
            self.step()
            self.restore_sql_state(incoming)
            names = [part.name for part in ast.walk(case.pattern)
                     if getattr(part, 'name', None)]
            names += [part.rest for part in ast.walk(case.pattern)
                      if getattr(part, 'rest', None)]
            self.bind_value_facts(names, subject_facts)
            truth = None
            if case.guard is not None:
                self.visit(case.guard)
                truth = self.literal_truth(case.guard)
                if truth is None:
                    self.note_possible_raise()
            guarded = self.sql_state()
            if truth is not False:
                flow = self.merge_flows(flow, self.statements(case.body, guarded))
            if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None:
                if case.guard is None or truth is True:
                    exhaustive = True
                    break
            # A failed guard may still have executed assignments that are
            # visible to later alternatives and the unmatched successor.
            if case.guard is not None and truth is not True:
                incoming = self.join_sql_states(incoming, guarded)
        if not exhaustive:
            flow = self.merge_flows(flow, {'normal': incoming})
        self.restore_sql_state(flow.get('normal', incoming))
        return flow

    def is_guarded(self, node):
        """The exact binding was checked on every path to this evaluation."""
        return bool(self.sanitizers) and validation_key(node) in self.validated

    def invalidate_attribute_validations(self):
        self.validated = {key for key in self.validated if '.' not in key}
        self._attribute_epoch += 1

    def invalidate_validation(self, names):
        roots = set(names)
        for name in roots:
            self._binding_epochs[name] = self._binding_epochs.get(name, 0) + 1
        self.validated = {key for key in self.validated if key.split('.')[0] not in roots}

    def validation_epoch(self, node):
        key = validation_key(node)
        if key is None:
            return None
        return (self._binding_epochs.get(key.split('.')[0], 0), self._attribute_epoch)

    def value_nodes(self, node):
        """Traverse value contributors, excluding format_map lookup keys."""
        yield node
        if node in self._evaluated_values:
            return
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
                node.func.attr == 'format_map'):
            yield from self.value_nodes(node.func.value)
            for argument in node.args:
                values = argument.values if isinstance(argument, ast.Dict) else [argument]
                for value in values:
                    yield from self.value_nodes(value)
            for keyword in node.keywords:
                yield from self.value_nodes(keyword.value)
        else:
            for child in ast.iter_child_nodes(node):
                yield from self.value_nodes(child)

    def names_in(self, node):
        return {child.id for child in self.value_nodes(node) if isinstance(child, ast.Name)}

    def unsafe_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.unsafe_sql_vars)

    def weak_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.weak_sql_vars)

    def classify_expr(self, node):
        # GH #94: provenance of one interpolated value. Names tainted by an
        # interpolated-SQL assignment count as tainted here too.
        if node in self._evaluated_values:
            return self._evaluated_values[node][4]
        if isinstance(node, ast.Constant):
            return 'static'
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            # Load/Store context nodes are syntax, not unknown values. The
            # contents of a literal collection determine its provenance and
            # that of items projected by a nested comprehension clause.
            return max((self.classify_expr(item) for item in node.elts),
                       key=RISK_ORDER.__getitem__, default='static')
        if isinstance(node, ast.JoinedStr):
            risk = 'static'
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    risk = max_risk(risk, self.classify_expr(part.value))
            return risk
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return max_risk(self.classify_expr(node.left), self.classify_expr(node.right))
        if isinstance(node, ast.Name):
            if node.id in self.value_risks:
                risk = self.value_risks[node.id]
                return 'unknown' if risk == 'tainted' and self.is_guarded(node) else risk
            if node.id in self.param_names or node.id in self.unsafe_sql_vars:
                # GH #133: a validated identifier is still not provably
                # static, so it drops one tier to Warning rather than
                # disappearing. That is enough for a gate to tell a checked
                # table name from a request parameter in an f-string, and it
                # cannot hide an injection the way silence would.
                return 'unknown' if self.is_guarded(node) else 'tainted'
            return self.name_risk.get(node.id, 'unknown')
        if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript, ast.Await)):
            # A value produced BY a sanitizer is safe by that function's own
            # contract — `quote_ident(x)` returns a quoted identifier — so it
            # is static rather than merely downgraded (GH #133).
            if is_sanitizer_call(node, self.sanitizers, self.bindings):
                return 'static'
            return 'unknown' if self.is_guarded(node) else 'tainted'
        risk = None
        for child in ast.iter_child_nodes(node):
            child_risk = self.classify_expr(child)
            risk = child_risk if risk is None else max_risk(risk, child_risk)
        return risk if risk is not None else 'unknown'

    def interpolated_sql_severity(self, node, require_sql=True):
        # GH #94: an interpolated SQL string is Critical only when at least one
        # interpolated value can carry external data. Provably-constant
        # interpolants are as safe as a literal (no finding); plain names of
        # unknown provenance surface as Warning.
        sql_node = node
        if isinstance(node, ast.JoinedStr):
            parts = [part.value for part in node.values if isinstance(part, ast.FormattedValue)]
            if not parts:
                return None
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            parts = [node.right]
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            parts = [node.left, node.right]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {'format', 'format_map'}:
            parts = list(node.args) + [kw.value for kw in node.keywords]
            if node.func.attr == 'format_map':
                parts = [value for part in parts
                         for value in (part.values if isinstance(part, ast.Dict) else [part])]
            sql_node = node.func.value
        else:
            return None
        if require_sql and not self.has_sql_template(sql_node):
            return None
        risk = 'static'
        for part in parts:
            risk = max_risk(risk, self.classify_expr(part))
        if risk == 'static':
            return None
        return 'critical' if risk == 'tainted' else 'warning'

    def contains_interpolation(self, node):
        if isinstance(node, ast.JoinedStr) and any(isinstance(part, ast.FormattedValue) for part in node.values):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)) and not all_static_strings(node):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {'format', 'format_map'}:
            return True
        return any(self.contains_interpolation(child) for child in ast.iter_child_nodes(node))

    def sql_risk(self, node, require_sql=True):
        # Worst severity over the expression: None (safe), 'warning', 'critical'.
        worst = None
        for child in self.value_nodes(node):
            if child in self._evaluated_values:
                severity = self._evaluated_values[child][0 if require_sql else 1]
            elif isinstance(child, ast.Name):
                if require_sql:
                    severity = ('critical' if child.id in self.unsafe_sql_vars else
                                'warning' if child.id in self.weak_sql_vars else None)
                else:
                    severity = self.fragment_sql_vars.get(child.id)
            else:
                severity = self.interpolated_sql_severity(child, require_sql=require_sql)
            if severity == 'critical':
                return 'critical'
            if severity == 'warning':
                worst = join_sql_risks(worst, severity)
        return worst

    def has_sql_template(self, node):
        if node in self._evaluated_values:
            return self._evaluated_values[node][3]
        return (looks_like_sql(node, self.text) or any(
            self._evaluated_values[child][3] if child in self._evaluated_values else
            isinstance(child, ast.Name) and child.id in self.sql_template_vars
            for child in self.value_nodes(node)))

    def select_risk(self, node):
        """Risk of raw SQL mapping values, retaining the distinction on aliases."""
        if node in self._evaluated_values:
            return self._evaluated_values[node][2]
        if isinstance(node, ast.Name):
            return self.select_sql_vars.get(node.id)
        if isinstance(node, ast.Dict):
            return join_sql_risks(*(
                self.select_risk(value) if key is None else self.sql_risk(value, require_sql=False)
                for key, value in zip(node.keys, node.values)
            ))
        if isinstance(node, ast.IfExp):
            return join_sql_risks(self.select_risk(node.body), self.select_risk(node.orelse))
        return self.sql_risk(node, require_sql=False)

    def value_facts(self, value):
        if value in self._evaluated_values:
            return self._evaluated_values[value]
        return (self.sql_risk(value), self.sql_risk(value, require_sql=False),
                self.select_risk(value), self.has_sql_template(value), self.classify_expr(value),
                self.generator_bindings.get(value.id, frozenset()) if isinstance(value, ast.Name) else frozenset())

    def bind_value_facts(self, names, facts):
        self.invalidate_validation(names)
        risk, fragment_risk, select_risk, template, provenance = facts[:5]
        self.store_sql_risk(names, risk)
        for name in names:
            references = self.generator_refs(facts)
            if references:
                self.generator_bindings[name] = references
            else:
                self.generator_bindings.pop(name, None)
            self.value_risks[name] = provenance
            for store, value in ((self.fragment_sql_vars, fragment_risk),
                                 (self.select_sql_vars, select_risk)):
                if value is None:
                    store.pop(name, None)
                else:
                    store[name] = value
            if template:
                self.sql_template_vars.add(name)
            else:
                self.sql_template_vars.discard(name)

    def assignment_bindings(self, target, value):
        # Capture every RHS value before binding any target. A swap is not
        # two sequential assignments; matching tuple/list elements retain
        # separate facts rather than tainting every target with their union.
        if (isinstance(target, (ast.Tuple, ast.List)) and
                isinstance(value, (ast.Tuple, ast.List)) and
                len(target.elts) == len(value.elts) and
                not any(isinstance(item, ast.Starred) for item in target.elts + value.elts)):
            return [binding for left, right in zip(target.elts, value.elts)
                    for binding in self.assignment_bindings(left, right)]
        return [(binding_target_names(target), self.value_facts(value))]

    def target_names(self, targets):
        names = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                names.extend(elt.id for elt in target.elts if isinstance(elt, ast.Name))
        return names

    def mark_assignment(self, names, value):
        self.bind_value_facts(names, self.value_facts(value))

    def store_sql_risk(self, names, risk):
        if risk == 'critical':
            for name in names:
                self.unsafe_sql_vars.add(name)
                self.weak_sql_vars.discard(name)
        elif risk == 'warning':
            for name in names:
                self.weak_sql_vars.add(name)
                self.unsafe_sql_vars.discard(name)
        else:
            for name in names:
                self.unsafe_sql_vars.discard(name)
                self.weak_sql_vars.discard(name)

    def visit_Assign(self, node):
        self.visit(node.value)
        pending = [binding for target in node.targets
                   for binding in self.assignment_bindings(target, node.value)]
        for target in node.targets:
            self.visit(target)
        for names, facts in pending:
            self.bind_value_facts(names, facts)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.mark_assignment([node.target.id], node.value)
        self.visit(node.target)
        self.visit(node.annotation)

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self.mark_assignment(binding_target_names(node.target), node.value)
        self._evaluated_values[node] = self.value_facts(node.value)

    def visit_Delete(self, node):
        for target in node.targets:
            self.visit(target)
            self.bind_value_facts(binding_target_names(target), (None, None, None, False, 'unknown'))

    def visit_AugAssign(self, node):
        self.visit(node.target)
        left = self.value_facts(node.target)
        self.visit(node.value)
        self.note_possible_raise()
        if isinstance(node.target, ast.Name):
            # += reads its left value before evaluating the RHS, unlike a
            # fresh lookup of the same name after an RHS assignment expression.
            self._evaluated_values[node.target] = left
            value = ast.copy_location(ast.BinOp(left=node.target, op=node.op, right=node.value), node)
            self.mark_assignment([node.target.id], value)

    def sql_argument(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        if short in EXECUTE_METHODS:
            if node.args and not isinstance(node.args[0], ast.Starred):
                return node.args[0]
            keywords = SQL_ARGUMENT_KEYWORDS.get(short, frozenset())
            for keyword in node.keywords:
                if keyword.arg in keywords:
                    return keyword.value
            if node.args:
                return node.args[0]
        if short == 'extra':
            for keyword in node.keywords:
                if keyword.arg == 'where':
                    return keyword.value
        return None

    def sql_arguments(self, node):
        """Yield SQL expressions and their statement/fragment/mapping context.

        Django extra(select, where, params, ...) accepts SQL fragments, not
        complete statements. Its select dictionary keys are result aliases;
        only the values are raw SQL. Do not inspect params/select_params.
        """
        if call_name(node.func).rsplit('.', 1)[-1] != 'extra':
            argument = self.sql_argument(node)
            if argument is not None:
                yield argument, 'statement'
            return
        for index, name in enumerate(('select', 'where')):
            argument = next((keyword.value for keyword in node.keywords
                             if keyword.arg == name), None)
            if argument is None and len(node.args) > index:
                # An unknown *args expansion makes subsequent positions
                # ambiguous. Explicit keywords above remain identifiable.
                if not any(isinstance(arg, ast.Starred) for arg in node.args[:index + 1]):
                    argument = node.args[index]
            if argument is None:
                continue
            yield argument, 'select' if name == 'select' else 'fragment'

    def visit_Call(self, node):
        known_builtin = (isinstance(node.func, ast.Name) and self.builtin_is_unshadowed(node.func.id)
                         and node.func.id in {'list', 'tuple', 'set', 'frozenset', 'sorted', 'min', 'max', 'sum',
                                              'any', 'all', 'iter', 'str', 'repr', 'bool', 'id', 'type'})
        if not known_builtin:
            self.note_possible_raise()
        # The sink's own first line is what a guard has to precede (GH #133).
        # Using the sink line rather than the interpolated value's line keeps
        # a guard written inside the same multi-line call from counting.
        is_sink = bool(list(self.sql_arguments(node)))
        previous_sink = self.sink_lineno
        if is_sink:
            self.sink_lineno = node.lineno
        argument_epochs = {}
        try:
            self.visit(node.func)
            for argument in node.args:
                self.visit(argument)
                argument_epochs[argument] = self.validation_epoch(argument)
            for keyword in node.keywords:
                self.visit(keyword.value)
                argument_epochs[keyword.value] = self.validation_epoch(keyword.value)
            self.generator_call(node)
            # All effects have now occurred, but each argument retains its
            # own evaluation-time value. Markers suppress the emitted rule in
            # find(), never execution.
            if is_sink:
                self.classify_sink(node)
        finally:
            self.sink_lineno = previous_sink
        stable = {argument for argument, epoch in argument_epochs.items()
                  if epoch is not None and epoch == self.validation_epoch(argument)}
        if not is_sanitizer_call(node, self.sanitizers, self.bindings):
            self.invalidate_attribute_validations()
        self.note_possible_raise()
        # Only successful completion establishes a proof. The pending error
        # store above must remain unvalidated when a handler catches failure.
        self.validated.update(call_validated_segments(
            node, self.text, self.sanitizers, self.sanitizer_summaries, stable, self.bindings))

    def classify_sink(self, node):
        worst = None
        for argument, context in self.sql_arguments(node):
            risk = (self.select_risk(argument) if context == 'select' else
                    self.sql_risk(argument, require_sql=context == 'statement'))
            if risk == 'critical':
                worst = risk
                break
            if risk == 'warning':
                worst = risk
        # Fixed-point visits must not multiply diagnostics. Retain the worst
        # reachable severity for this exact AST call (not just its line).
        previous = self._sink_risks.get(id(node))
        if worst is not None and (previous is None or worst == 'critical'):
            self._sink_risks[id(node)] = (worst, node.lineno, source_line(self.lines, node.lineno))


def find(files: Sequence[Path], *, max_steps=100_000) -> Iterable[tuple[str, Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            with tokenize.open(path) as stream:
                text = stream.read()
            tree = ast.parse(text, filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise SQLFlowLimit(f'Cannot analyze Python SQL source {path}: {exc}; analysis is incomplete') from exc
        lines = text.splitlines()
        param_names, name_risk = build_provenance(tree)
        sanitizers = configured_sanitizers()
        budget = [max_steps]
        bindings = SanitizerBindings(tree, configured_sanitizer_targets(), budget) if sanitizers else None
        summaries = build_sanitizer_summaries(tree, sanitizers, text=text, budget=budget, bindings=bindings)
        analyzer = SQLInjectionAnalyzer(
            text,
            lines,
            param_names,
            name_risk,
            sanitizers,
            summaries,
            max_steps=max_steps,
            budget=budget,
            bindings=bindings,
        )
        analyzer.visit(tree)
        suppressions = build_index(text, "python") if may_have_markers(text) else SuppressionIndex()
        for line_no, code in analyzer.issues:
            if not suppressions.is_suppressed(line_no, RULE_CRITICAL):
                yield RULE_CRITICAL, path, line_no, 1, code[:240]
        for line_no, code in analyzer.warn_issues:
            if not suppressions.is_suppressed(line_no, RULE_WARNING):
                yield RULE_WARNING, path, line_no, 1, code[:240]
