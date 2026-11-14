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

Statement-owned `ubs:ignore` comments suppress only the emitted SQL tier's selected rule ID.

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
import builtins
import os
import re
import tokenize
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.suppression import SuppressionIndex, build_index, may_have_markers
from ubs_core.taint_flow import AnalysisLimit

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
LIST_MUTATORS = frozenset({'append', 'extend', 'insert', 'clear', 'pop', 'remove', 'reverse', 'sort',
                           '__setitem__', '__delitem__', '__iadd__', '__imul__', '__init__'})
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


REFLECTIVE_LOOKUPS = frozenset({
    'getattr', '__getattribute__', '__getattr__', 'attrgetter', 'methodcaller',
    'globals', 'locals', 'vars', 'eval', 'exec', '__builtins__', '__import__',
    'builtins', '_getframe', 'currentframe', 'getouterframes', 'stack',
    '__globals__', '__self__',
    'f_globals', 'f_locals', 'f_builtins', '__dict__', 'modules', 'import_module', '*',
})


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
        self.parents = {}
        self.owner_scopes = {}
        self.member_writes = set()
        self.indirect_rebindings = set()
        self.calls = []
        self._sql_capability_candidates = []
        self.name_loads = {}
        self.direct_callees = set()
        self.literal_assignments = {}
        self.key_callbacks = set()
        self.predicate_callbacks = set()
        self.escaped_imports = set()
        self.dynamic_namespace = False
        self.builtin_namespace = False
        self.regex_namespace_escape = False
        self.reflective_member_writes = False
        self._walk(tree, self._scope(tree, None))
        self._local_sql_effects = None
        self._function_calls = {}
        self._escaped_classes = {}
        self._forwarding_cache = {}
        self._closed_function_cache = {}
        self._closed_function_calls = {}
        self._process_namespace_closed = None
        self._process_forwarders = set()
        self._instrumentation_lists = {}
        self._instrumentation_forwarders = set()
        self._possible_sql_imports = {}
        self._possible_sql_methods = {}
        self._saved_sql_methods = {}
        self._closed_method_aliases = {}
        self._constructed_receivers = {}
        self._sql_method_captures = {}
        self._captured_receivers = {}
        self._escaped_sql_methods = None
        self._sql_escape_coverage = {}
        self._sql_facade_call_coverage = {}
        self.sql_method_escape_owners = frozenset()
        self._binding_resolutions = {}
        self._sql_binding_cells = {}
        self._sql_facade_flow = None
        self.independent_functions = self._independent_functions()
        for scope in self.owner_scopes.values():
            scope['capture_barriers'] = frozenset(scope['capture_barriers'])
        for reference in self.name_loads.get('getattr', ()):
            if (reference not in self.direct_callees
                    and self.resolve(reference) in (None, ('unbound', 'getattr'))):
                # Once the reflective callable escapes into an alias,
                # container or partial, its later attribute names need not
                # be visible at a direct getattr call site.
                self.dynamic_namespace = True
                self.builtin_namespace = True
                break
        for name in ('setattr', 'delattr'):
            for reference in self.name_loads.get(name, ()):
                if (reference not in self.direct_callees
                        and self.resolve(reference) in (None, ('unbound', name))):
                    # Aliasing/exporting the builtin preserves its ability
                    # to replace an execution method without a named call.
                    self.reflective_member_writes = True
        if any(isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
               and node.attr in {'setattr', 'delattr', '__setattr__', '__delattr__'}
               and node not in self.direct_callees for node in self.scope_of):
            self.reflective_member_writes = True
        for call in self.calls:
            if call_name(call.func).rsplit('.', 1)[-1] in {'setattr', 'delattr', '__setattr__', '__delattr__'}:
                self.reflective_member_writes = True
            if isinstance(call.func, ast.Name) and call.func.id in {'exec', 'eval', 'globals', 'locals'}:
                self.dynamic_namespace = True
            if (isinstance(call.func, ast.Name)
                    and 'getattr' in self.name_loads
                    and not self.in_independent_body(call)
                    and (any(isinstance(argument, ast.Starred) for argument in call.args[:2])
                         or len(call.args) >= 2 and (
                             (names := self.attribute_name_options(call.args[1])) is None
                             or bool(names & {
                                 '_getframe', 'currentframe', 'f_globals', 'f_locals', 'f_builtins',
                                 '__builtins__', '__dict__', '__globals__', '__self__',
                                 '__getattribute__', '__getattr__',
                                 'modules', 'import_module', 'attrgetter', 'methodcaller'})))
                    and ((resolved_lookup := self.resolve(call.func)) == ('unbound', 'getattr')
                         or call.func.id == 'getattr' and resolved_lookup is None)):
                # An aliased or computed getattr can expose the same frame
                # dictionaries as direct attribute access. A dynamic name is
                # not proof that the lookup avoids that capability. Resolve
                # the callable lexically so an unrelated local helper does
                # not invalidate every builtin shape in the file.
                self.dynamic_namespace = True
                self.builtin_namespace = True
            if not targets:
                # Ownership-only resolution needs no sanitizer-import escape
                # classification. Lexical identity and namespace checks above
                # still apply; configured sanitizer targets keep the full path.
                continue
            for argument in [*call.args, *(kw.value for kw in call.keywords)]:
                resolved = self.resolve(argument)
                if resolved and resolved[0] == 'import':
                    self.escaped_imports.add(resolved[1])
        # Resolve deferred-body relevance only after namespace and escape
        # capabilities are known. A proven local raw helper must not abort
        # analysis of an independent function that really executes SQL.
        self.independent_functions = self._independent_functions(resolve_calls=True)

    def attribute_name_options(self, node, seen=frozenset()):
        """Finite literal names on normal completion, never an arbitrary getter.

        Literal lookup tables are a common way to select an ordinary field.
        A failed lookup raises; it cannot synthesize a frame-namespace name.
        Follow only a single earlier, unconditional lexical assignment, so
        a parameter, branch, rebinding or reflective name stays unresolved.
        """
        self.budget[0] -= 1
        if self.budget[0] < 0:
            raise SQLFlowLimit('SQL attribute-name budget exceeded; analysis is incomplete')
        if node in seen:
            return None
        seen = seen | {node}
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return frozenset({node.value})
        if isinstance(node, ast.Name) and node.id not in self.indirect_rebindings:
            scope = self.scope_of.get(node)
            while scope is not None and node.id not in scope['names']:
                previous = scope['node']
                scope = scope['parent']
                if not isinstance(previous, ast.ClassDef):
                    while scope is not None and isinstance(scope['node'], ast.ClassDef):
                        scope = scope['parent']
            if scope is not None and len(scope['names'][node.id]) == 1:
                assignment = self.literal_assignments.get((scope['node'], node.id))
                if assignment is not None and assignment.lineno < node.lineno:
                    return self.attribute_name_options(assignment.value, seen)
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.attribute_name_options(node.left, seen)
            right = self.attribute_name_options(node.right, seen)
            if left is not None and right is not None and len(left) * len(right) <= 32:
                return frozenset(a + b for a in left for b in right)
            return None
        if isinstance(node, ast.Subscript):
            if self.selector_has_opaque_effects(node.slice):
                return None
            if (isinstance(node.value, ast.Dict)
                    and all(isinstance(key, ast.Constant) and type(key.value) in {str, int, float, bool, type(None)}
                            for key in node.value.keys)):
                values = node.value.values
            elif isinstance(node.value, (ast.Tuple, ast.List)):
                values = node.value.elts
            else:
                return None
            if not values or len(values) > 32:
                return None
            choices = [self.attribute_name_options(value, seen) for value in values]
            if all(choice is not None for choice in choices):
                names = frozenset().union(*choices)
                return names if len(names) <= 32 else None
        return None

    def selector_has_opaque_effects(self, node, seen=frozenset()):
        """Do not confuse a finite field-name result with selector purity.

        A constructed key, local callback protocol, or replaced selector can
        modify SQL/namespace state while indexing the literal table. Ordinary
        input names retain the pass's existing in-file callback boundary.
        """
        self.budget[0] -= 1
        if self.budget[0] < 0:
            raise SQLFlowLimit('SQL selector budget exceeded; analysis is incomplete')
        if node in seen:
            return True
        if isinstance(node, ast.Constant) and type(node.value) in {str, int, float, bool, type(None)}:
            return False
        if not isinstance(node, ast.Name) or node.id in self.indirect_rebindings:
            return True
        scope = self.scope_of.get(node)
        while scope is not None and node.id not in scope['names']:
            scope = scope['parent']
        if scope is not None:
            if len(scope['names'][node.id]) != 1:
                return True
            assignment = self.literal_assignments.get((scope['node'], node.id))
            if assignment is not None:
                return (assignment.lineno >= node.lineno
                        or self.selector_has_opaque_effects(assignment.value, seen | {node}))
        return bool(self.key_callbacks)

    def _independent_functions(self, *, resolve_calls=False):
        """Deferred, unreferenced module helpers cannot affect an in-file sink.

        Keep any nested SQL spelling, namespace access, mutation of outer
        bindings, decorator, alias or callback reference on the full path.
        Defaults and annotations belong to the enclosing scope and are still
        evaluated by visit_FunctionDef before this body-only admission test.
        """
        independent = set()
        for function, scope in self.owner_scopes.items():
            if (not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
                    or scope['parent'] is None
                    or not isinstance(scope['parent']['node'], ast.Module)
                    or function.decorator_list or self.name_loads.get(function.name)
                    or len(scope['parent']['names'].get(function.name, ())) != 1
                    or function in self.local_sql_effects()):
                continue
            if resolve_calls and function in self.independent_functions:
                independent.add(function)
                continue
            relevant = False
            for statement in function.body:
                for node in ast.walk(statement):
                    self.budget[0] -= 1
                    if self.budget[0] < 0:
                        raise SQLFlowLimit('SQL relevance budget exceeded; analysis is incomplete')
                    if (isinstance(node, ast.Call) and sql_sink_name(node, self if resolve_calls else None)
                            or isinstance(node, (ast.Global, ast.Nonlocal))
                            or isinstance(node, ast.Name) and node.id in {
                                '__builtins__', '__import__', 'globals', 'locals', 'vars', 'exec', 'eval'}):
                        relevant = True
                        break
                if relevant:
                    break
            if not relevant:
                independent.add(function)
        return frozenset(independent)

    def in_independent_body(self, node):
        scope = self.scope_of.get(node)
        while scope is not None:
            if scope['node'] in self.independent_functions:
                return True
            scope = scope['parent']
        return False

    def local_sql_effects(self):
        """Reachable modeled SQL operations in stable same-file helpers.

        A user-defined execute is not a database API merely by spelling.
        Wrappers that reach an unresolved SQL-family call remain sinks at
        their callers, including indirect wrappers and recursive groups.
        """
        if self._local_sql_effects is not None:
            return self._local_sql_effects
        functions = {node for node in self.owner_scopes
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))}
        callers = {node: set() for node in functions}
        effects = set()
        for call in self.calls:
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL call graph budget exceeded; analysis is incomplete')
            scope = self.scope_of[call]
            while scope is not None and scope['node'] not in functions:
                scope = scope['parent']
            if scope is None:
                continue
            function = scope['node']
            self._function_calls.setdefault(function, []).append(call)
            target = self.resolve(call.func)
            if target and target[0] == 'function':
                callers[target[1]].add(function)
            elif (sql_sink_name(call)
                  or target and target[0] == 'import'
                  and target[1].rsplit('.', 1)[-1] in EXECUTE_METHODS | {'extra'}
                  or self.unresolved_sql_aliases(call)):
                effects.add(function)
        for node, scope in self.scope_of.items():
            if (not isinstance(node, ast.Attribute) or node in self.direct_callees
                    or node.attr not in EXECUTE_METHODS | {'extra'}):
                continue
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL call graph budget exceeded; analysis is incomplete')
            while scope is not None and scope['node'] not in functions:
                scope = scope['parent']
            if scope is None:
                continue
            target = self.resolve(node)
            if target and target[0] == 'function':
                callers[target[1]].add(scope['node'])
            else:
                # Capturing cursor.execute into an alias or passing it to a
                # callback does not stop a local wrapper from being SQL-capable.
                effects.add(scope['node'])
        # Nested bodies still receive standalone analysis. Their sinks also
        # prevent an enclosing execute wrapper from being certified non-SQL.
        for function in functions:
            scope = self.owner_scopes[function]['parent']
            while scope is not None and scope['node'] not in functions:
                scope = scope['parent']
            if scope is not None:
                callers[function].add(scope['node'])
        pending = list(effects)
        while pending:
            for caller in callers[pending.pop()]:
                self.budget[0] -= 1
                if self.budget[0] < 0:
                    raise SQLFlowLimit('SQL call graph budget exceeded; analysis is incomplete')
                if caller not in effects:
                    effects.add(caller)
                    pending.append(caller)
        self._local_sql_effects = frozenset(effects)
        return self._local_sql_effects

    def sql_facade_flow(self):
        """Opaque forwards reached through invoked local SQL-family APIs.

        An ordinary callback is not a database API by default. A local
        execute/raw facade that constructs SQL internally, however, cannot
        be certified harmless by inspecting only its caller's first value.
        Reuse the lexical call graph and retain only groups with actual SQL
        literal syntax. The flow visitor must still establish dynamic SQL
        provenance before refusing an opaque call or discarded heap write.
        """
        if self._sql_facade_flow is not None:
            return self._sql_facade_flow
        self.local_sql_effects()
        pending = []
        for call in self.calls:
            target = self.resolve(call.func)
            if (target and target[0] == 'function'
                    and (call_name(call.func).rsplit('.', 1)[-1] in EXECUTE_METHODS | {'extra'}
                         or getattr(target[1], 'name', '') in EXECUTE_METHODS | {'extra'})):
                pending.append(target[1])
        functions, opaque = set(), set()
        while pending:
            function = pending.pop()
            if function in functions:
                continue
            functions.add(function)
            for call in self._function_calls.get(function, ()):
                self.budget[0] -= 1
                if self.budget[0] < 0:
                    raise SQLFlowLimit('SQL facade call graph budget exceeded; analysis is incomplete')
                target = self.resolve(call.func)
                if target and target[0] == 'function':
                    pending.append(target[1])
                elif target and target[0] == 'class':
                    for name in ('__new__', '__init__'):
                        for member in self.owner_scopes[target[1]]['names'].get(name, ()):
                            if member and member[0] == 'function':
                                pending.append(member[1])
                    opaque.add(call)
                elif not (sql_sink_name(call, self) or self.unresolved_sql_aliases(call)
                          or self.process_call(call, target)):
                    opaque.add(call)
        # Query templates may be module constants or lexical captures. Their
        # ownership is broader than the called facade, while the actual
        # forwarding check below still requires evaluated SQL provenance.
        template_owners = {None}
        for function in functions:
            scope = self.owner_scopes[function]
            while scope is not None:
                self.budget[0] -= 1
                if self.budget[0] < 0:
                    raise SQLFlowLimit('SQL facade scope budget exceeded; analysis is incomplete')
                if isinstance(scope['node'], (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    template_owners.add(scope['node'])
                scope = scope['parent']
        has_template = False
        if opaque:
            for node in self.scope_of:
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str) or not SQL_RE.search(node.value):
                    continue
                if isinstance(self.parents.get(node), ast.Expr):
                    continue  # a docstring is not query construction
                if self.function_owner(node) in template_owners:
                    has_template = True
                    break
        self._sql_facade_flow = (frozenset(functions), frozenset(opaque)) if has_template else (frozenset(), frozenset())
        return self._sql_facade_flow

    def function_owner(self, node):
        scope = self.scope_of.get(node)
        while scope is not None:
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL facade scope budget exceeded; analysis is incomplete')
            if isinstance(scope['node'], (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return scope['node']
            scope = scope['parent']
        return None

    def class_escapes(self, owner, captured_method=None):
        cache_key = owner if captured_method is None else (owner, captured_method)
        if cache_key in self._escaped_classes:
            return self._escaped_classes[cache_key]
        if (owner.bases or owner.keywords or owner.decorator_list
                or {'__new__', '__getattribute__', '__getattr__', '__setattr__', '__delattr__'}
                    & self.owner_scopes[owner]['names'].keys()):
            self._escaped_classes[cache_key] = True
            return True
        # Resolve the members from the closed class body, not from the global
        # member-write index. A write to another record's equally named field
        # cannot replace this instance's method if the receiver never escapes.
        methods = {}
        for statement in owner.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(not isinstance(decorator, ast.Name)
                       or decorator.id not in {'classmethod', 'staticmethod'}
                       or self.resolve(decorator) != ('unbound', decorator.id)
                       for decorator in statement.decorator_list):
                    self._escaped_classes[cache_key] = True
                    return True
                if len(self.owner_scopes[owner]['names'].get(statement.name, ())) != 1:
                    self._escaped_classes[cache_key] = True
                    return True
                methods[statement.name] = statement
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                if (any(not isinstance(target, ast.Name) for target in targets)
                        or value is not None and not isinstance(value, ast.Constant)):
                    # An unknown class value can be a descriptor whose
                    # __set_name__/__get__ receives the owner implicitly.
                    self._escaped_classes[cache_key] = True
                    return True
            elif not (isinstance(statement, ast.Pass)
                      or isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)):
                self._escaped_classes[cache_key] = True
                return True
        # Recursive lexical resolution during an escape check must not turn a
        # circular alias into a receiver proof.
        self._escaped_classes[cache_key] = True
        names = {owner.name}
        for statement in owner.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.update(_positional_parameters(statement)[:1])
        escaped = False
        for name in names:
            for reference in self.name_loads.get(name, ()):
                target = self.resolve(reference)
                if target is None and captured_method is not None:
                    target = self.captured_receiver(reference)
                if not target or target[0] not in {'class', 'receiver'} or target[1] is not owner:
                    continue
                scope = self.scope_of.get(reference) if target[0] == 'receiver' else None
                while scope is not None and scope['parent'] is not self.owner_scopes[owner]:
                    if isinstance(scope['node'], (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                        escaped = True
                        break
                    if (isinstance(scope['node'], ast.GeneratorExp)
                            and not self.closed_receiver_generator(scope['node'], owner)):
                        escaped = True
                        break
                    scope = scope['parent']
                if escaped:
                    break
                parent = self.parents.get(reference)
                if isinstance(parent, ast.Attribute) and parent.value is reference:
                    method = methods.get(parent.attr)
                    decorators = [call_name(value) for value in method.decorator_list] if method else []
                    if (captured_method is not None and parent.attr == captured_method.attr
                            and isinstance(parent.ctx, ast.Store)
                            and self.saved_method_capture_is_stable(captured_method)):
                        # Replacing this attribute after capture does not
                        # replace the function/receiver already bound in the
                        # saved method. The capture proof admits only later
                        # ordinary assignments in this same function body.
                        continue
                    if (method is not None
                            and (parent in self.direct_callees or self.closed_method_alias(parent))
                            and (decorators in (['staticmethod'], ['classmethod'])
                                 or target[0] == 'receiver' and target[2])):
                        continue
                    if (method is None and target[0] == 'receiver' and target[2]
                            and not parent.attr.startswith('__')):
                        # Plain instance fields have no descriptor dispatch.
                        # This proves only that reading/writing the field does
                        # not export its owner; the value may still carry SQL,
                        # aliases or an opaque callback, checked separately.
                        continue
                    escaped = True
                    break
                if target[0] == 'class' and isinstance(parent, ast.Call) and parent.func is reference:
                    use = self.parents.get(parent)
                    if isinstance(use, ast.Expr):
                        continue
                    if (isinstance(use, ast.Attribute) and use.value is parent
                            and use in self.direct_callees):
                        member = self.lookup(use.attr, self.owner_scopes[owner])
                        if member and member[0] == 'function':
                            continue
                    if isinstance(use, (ast.Assign, ast.AnnAssign)) and use.value is parent:
                        targets = use.targets if isinstance(use, ast.Assign) else [use.target]
                        if len(targets) == 1:
                            stored = self.constructed_receiver(targets[0])
                            if stored is not None and stored[1] is owner:
                                continue
                    # Other storage/construction contexts lack a closed
                    # lexical owner even if the class name stays unmodified.
                    escaped = True
                    break
                escaped = True
                break
            if escaped:
                break
        self._escaped_classes[cache_key] = escaped
        return escaped

    def constructed_receiver(self, reference):
        """A single local allocation whose identity stays in its lexical cell.

        The class escape proof separately checks constructor/method bodies,
        descriptors and class aliases. This proof follows every use of the
        allocated instance, so a local variable does not itself constitute an
        export while passing, aliasing or capturing that variable still does.
        """
        if not isinstance(reference, ast.Name):
            return None
        scope = self.lexical_owner(reference)
        if (scope is None or not isinstance(scope['node'], (ast.FunctionDef, ast.AsyncFunctionDef))
                or len(scope['names'].get(reference.id, ())) != 1
                or reference.id in scope['capture_barriers']):
            return None
        key = (scope['node'], reference.id)
        if key in self._constructed_receivers:
            return self._constructed_receivers[key]
        self._constructed_receivers[key] = None
        assignment = self.literal_assignments.get(key)
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
            return None
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        if (len(targets) != 1 or not isinstance(targets[0], ast.Name)
                or not isinstance(assignment.value, ast.Call)):
            return None
        target = self.resolve(assignment.value.func)
        if not target or target[0] != 'class':
            return None
        owner = target[1]
        members = self.owner_scopes[owner]['names']
        if (owner.bases or owner.keywords or owner.decorator_list
                or {'__new__', '__getattribute__', '__getattr__', '__setattr__', '__delattr__'}
                    & members.keys()):
            return None
        for method in owner.body:
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL receiver ownership budget exceeded; analysis is incomplete')
            if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators = [call_name(value) for value in method.decorator_list]
            if decorators == ['staticmethod']:
                continue
            positional = _positional_parameters(method)
            if (not positional or positional[0] in self.indirect_rebindings
                    or self.owner_scopes[method]['names'].get(positional[0])
                        != [('receiver', owner, not decorators)]):
                # The class escape proof follows explicit receiver cells.
                # A receiver hidden in *args or lost to rebinding can export
                # the allocated object without a resolvable receiver load.
                # Saved bound methods have a separate capture-time proof;
                # this allocation-wide certificate cannot borrow it.
                return None
        for use in self.name_loads.get(reference.id, ()):
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL receiver ownership budget exceeded; analysis is incomplete')
            if self.lexical_owner(use) is not scope:
                continue
            if use.lineno <= assignment.lineno:
                return None
            cursor = self.scope_of.get(use)
            while cursor is not None and cursor is not scope:
                if isinstance(cursor['node'], (ast.FunctionDef, ast.AsyncFunctionDef,
                                                ast.Lambda, ast.GeneratorExp)):
                    return None
                cursor = cursor['parent']
            parent = self.parents.get(use)
            if (not isinstance(parent, ast.Attribute) or parent.value is not use
                    or parent.attr.startswith('__')):
                return None
            candidates = members.get(parent.attr, ())
            if candidates:
                if (len(candidates) != 1 or not candidates[0]
                        or candidates[0][0] != 'function'
                        or not isinstance(parent.ctx, ast.Load)
                        or parent not in self.direct_callees):
                    return None
        result = ('receiver', owner, True)
        self._constructed_receivers[key] = result
        return result

    def closed_receiver_generator(self, generator, owner):
        """A receiver capture stays private only during an eager consumption."""
        call = self.parents.get(generator)
        if (not isinstance(call, ast.Call) or generator not in call.args
                or any(isinstance(value, ast.Starred) for value in call.args)
                or any(keyword.arg is None for keyword in call.keywords)):
            return False
        target = self.resolve(call.func)
        consumers = {'list', 'tuple', 'set', 'frozenset', 'dict', 'sorted', 'sum', 'min', 'max', 'any', 'all'}
        if target and target[0] == 'unbound' and target[1] in consumers:
            return len(call.args) == 1 and not call.keywords
        if not target or target[0] != 'function' or not self.eager_function(target[1]):
            return False
        function = target[1]
        enclosing = self.owner_scopes[function]['parent']
        if enclosing is not None and isinstance(enclosing['node'], ast.ClassDef):
            if enclosing['node'] is not owner:
                return False
        elif (function.decorator_list or any(reference not in self.direct_callees
                and (resolved := self.resolve(reference)) and resolved[0] == 'function'
                and resolved[1] is function for reference in self.name_loads.get(function.name, ()))):
            # An eager-looking body is no guarantee about a decorator or an
            # exported callable whose code can retain the generator frame.
            return False
        parameters = _positional_parameters(function)[1 if target[2] else 0:]
        position = call.args.index(generator)
        if (position >= len(parameters) or function.args.vararg or function.args.kwarg
                or any(keyword.arg == parameters[position] for keyword in call.keywords)):
            return False
        for reference in self.name_loads.get(parameters[position], ()):
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL receiver capture budget exceeded; analysis is incomplete')
            scope = self.scope_of.get(reference)
            while scope is not None and isinstance(scope['node'], (ast.ListComp, ast.SetComp, ast.DictComp)):
                scope = scope['parent']
            if scope is not self.owner_scopes[function]:
                # Capturing the parameter in another deferred scope can
                # retain the generator and, through its frame, the receiver.
                cursor = scope
                while cursor is not None and cursor is not self.owner_scopes[function]:
                    cursor = cursor['parent']
                if cursor is not None:
                    return False
                continue
            parent = self.parents.get(reference)
            if (isinstance(parent, ast.For) and parent.iter is reference
                    or isinstance(parent, ast.comprehension) and parent.iter is reference
                    and not isinstance(self.parents.get(parent), ast.GeneratorExp)):
                continue
            if (isinstance(parent, ast.Call) and parent.args == [reference] and not parent.keywords
                    and self.resolve(parent.func) in {('unbound', name) for name in consumers}):
                continue
            return False
        return True

    def lexical_owner(self, node):
        """The lexical cell a name denotes, including captured outer cells."""
        if not isinstance(node, ast.Name) or node.id in self.indirect_rebindings:
            return None
        scope = self.scope_of.get(node)
        while scope is not None:
            if node.id in scope['names']:
                return scope
            child = scope['node']
            scope = scope['parent']
            if not isinstance(child, ast.ClassDef):
                while scope and isinstance(scope['node'], ast.ClassDef):
                    scope = scope['parent']
        return None

    def possible_sql_imports(self, node, seen=frozenset()):
        """Retain possible import identities when a stable alias is unproved.

        This is a refusal boundary, not an execution certificate. A saved
        alias can still reference an imported SQL callable after that source
        name is reassigned. The ordinary resolver intentionally rejects such
        multi-binding cells; losing their possible SQL identity would make a
        conditional replacement, or a capture before replacement, look clean.
        """
        if node in seen:
            return frozenset()
        if node in self._possible_sql_imports:
            return self._possible_sql_imports[node]
        self.budget[0] -= 1
        if self.budget[0] < 0:
            raise SQLFlowLimit('SQL alias resolution budget exceeded; analysis is incomplete')
        seen = seen | {node}
        possible = set()
        if isinstance(node, ast.Name):
            scope = self.sql_binding_cell(node.id, self.scope_of.get(node))
            owners = [scope] if scope is not None else []
            if node.id in self.indirect_rebindings:
                for candidate in self.owner_scopes.values():
                    self.budget[0] -= 1
                    if self.budget[0] < 0:
                        raise SQLFlowLimit('SQL alias cell budget exceeded; analysis is incomplete')
                    if (node.id in candidate['capture_barriers']
                            and self.sql_binding_cell(node.id, candidate) is scope):
                        owners.append(candidate)
            for owner in owners:
                for candidate in owner['names'].get(node.id, ()):
                    if candidate and candidate[0] == 'import':
                        possible.add(candidate[1])
                    elif candidate and candidate[0] == 'alias':
                        possible.update(self.possible_sql_imports(candidate[1], seen))
        elif isinstance(node, ast.Attribute):
            possible.update(name + '.' + node.attr for name in self.possible_sql_imports(node.value, seen))
        result = frozenset(possible)
        # A recursive alias edge has a context-dependent visited set. Only
        # memoize a complete root query, never a partial cycle projection.
        if len(seen) == 1:
            self._possible_sql_imports[node] = result
        return result

    def saved_sql_method(self, node, seen=frozenset()):
        """Resolve a stable saved method to its original receiver expression.

        A bound method does not become a new API when its local name changes.
        Keep the actual attribute, so local application methods still receive
        the same receiver/forwarding checks as a direct call. This deliberately
        leaves the general import/function resolver unchanged.
        """
        if node in seen:
            return None
        if not seen and node in self._saved_sql_methods:
            return self._saved_sql_methods[node]
        self.budget[0] -= 1
        if self.budget[0] < 0:
            raise SQLFlowLimit('SQL saved method resolution budget exceeded; analysis is incomplete')
        root = not seen
        seen = seen | {node}
        result = None
        if isinstance(node, ast.Attribute) and node.attr in EXECUTE_METHODS | {'extra'}:
            result = node
        elif isinstance(node, ast.Name) and node.id not in self.indirect_rebindings:
            source = self.local_alias_source(node)
            if source is not None:
                result = self.saved_sql_method(source, seen)
        if root:
            self._saved_sql_methods[node] = result
        return result

    def local_alias_source(self, node):
        """Select the value copied at an unconditional local assignment.

        A saved copy must not follow a later replacement of its source name.
        Multiple definitions are admitted only in one straight-line function
        body; branches, loops, exception paths and captured mutable cells keep
        the existing unresolved-binding boundary.
        """
        if not isinstance(node, ast.Name) or node.id in self.indirect_rebindings:
            return None
        scope = self.lexical_owner(node)
        candidates = scope['names'].get(node.id, ()) if scope is not None else ()
        if len(candidates) == 1:
            return candidates[0][1] if candidates[0] and candidates[0][0] == 'alias' else None
        if (not candidates or scope is not self.scope_of.get(node)
                or not isinstance(scope['node'], (ast.FunctionDef, ast.AsyncFunctionDef))):
            return None
        latest = None
        for candidate in candidates:
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL saved method assignment budget exceeded; analysis is incomplete')
            if not candidate or candidate[0] != 'alias':
                return None
            source = candidate[1]
            assignment = self.parents.get(source)
            if (not isinstance(assignment, (ast.Assign, ast.AnnAssign))
                    or assignment.value is not source or self.parents.get(assignment) is not scope['node']):
                return None
            position = assignment.end_lineno, assignment.end_col_offset
            if position <= (node.lineno, node.col_offset) and (latest is None or position > latest[0]):
                latest = position, source
        return latest[1] if latest is not None else None

    def saved_method_capture_is_stable(self, method):
        if method in self._sql_method_captures:
            return self._sql_method_captures[method]
        stable = (not self.dynamic_namespace and not self.reflective_member_writes
                  and not {'__code__', '__globals__', '__defaults__', '__kwdefaults__'} & self.member_writes)
        if stable and method.attr in self.member_writes:
            owner = self.scope_of.get(method)
            for node, scope in self.scope_of.items():
                self.budget[0] -= 1
                if self.budget[0] < 0:
                    raise SQLFlowLimit('SQL saved method capture budget exceeded; analysis is incomplete')
                if not (isinstance(node, ast.Attribute) and node.attr == method.attr
                        and isinstance(node.ctx, (ast.Store, ast.Del))):
                    continue
                assignment = self.parents.get(node)
                if (owner is None or scope is not owner
                        or not isinstance(owner['node'], (ast.FunctionDef, ast.AsyncFunctionDef))
                        or not isinstance(assignment, (ast.Assign, ast.AnnAssign))
                        or self.parents.get(assignment) is not owner['node']
                        or assignment.lineno <= method.lineno):
                    stable = False
                    break
        self._sql_method_captures[method] = stable
        return stable

    def saved_non_sql_replacement(self, call):
        """An unconditional replacement with the actual print builtin is not SQL."""
        if (not isinstance(call.func, ast.Name) or self.dynamic_namespace or self.builtin_namespace
                or self.reflective_member_writes):
            return False
        source, seen = call.func, set()
        while source not in seen:
            seen.add(source)
            copied = self.local_alias_source(source)
            if copied is None:
                break
            source = copied
        return source is not call.func and self.resolve(source) == ('unbound', 'print')

    def captured_receiver(self, node, seen=frozenset()):
        """Keep the original local receiver across later name assignments."""
        if node in seen:
            return None
        if not seen and node in self._captured_receivers:
            return self._captured_receivers[node]
        root = not seen
        seen = seen | {node}
        resolved = self.resolve(node)
        if resolved and resolved[0] in {'class', 'receiver'}:
            return resolved
        result = None
        if isinstance(node, ast.Name) and node.id not in self.indirect_rebindings:
            copied = self.local_alias_source(node)
            if copied is not None:
                result = self.captured_receiver(copied, seen)
            else:
                scope = self.lexical_owner(node)
                candidates = scope['names'].get(node.id, ()) if scope is not None else ()
                if (scope is self.scope_of.get(node) and candidates and candidates[0]
                        and candidates[0][0] == 'receiver'):
                    latest, closed = None, True
                    for target, target_scope in self.scope_of.items():
                        self.budget[0] -= 1
                        if self.budget[0] < 0:
                            raise SQLFlowLimit('SQL saved receiver binding budget exceeded; analysis is incomplete')
                        if not (target_scope is scope and isinstance(target, ast.Name)
                                and target.id == node.id and isinstance(target.ctx, (ast.Store, ast.Del))):
                            continue
                        assignment = self.parents.get(target)
                        if (not isinstance(assignment, (ast.Assign, ast.AnnAssign))
                                or self.parents.get(assignment) is not scope['node']
                                or assignment.value is None):
                            closed = False
                            break
                        position = assignment.end_lineno, assignment.end_col_offset
                        if position <= (node.lineno, node.col_offset) and (latest is None or position > latest[0]):
                            latest = position, assignment.value
                    if closed:
                        result = (self.captured_receiver(latest[1], seen) if latest is not None else candidates[0])
        if root:
            self._captured_receivers[node] = result
        return result

    def captured_method_target(self, method):
        if not self.saved_method_capture_is_stable(method):
            return None
        receiver = self.captured_receiver(method.value)
        if not receiver:
            return None
        owner = receiver[1]
        if owner.decorator_list or owner.bases or owner.keywords:
            return None
        candidates = self.owner_scopes[owner]['names'].get(method.attr, ())
        target = candidates[0] if len(candidates) == 1 else None
        if not target or target[0] != 'function':
            return None
        decorators = [call_name(value) for value in target[1].decorator_list]
        if (decorators not in ([], ['classmethod'], ['staticmethod']) or any(
                self.resolve(value) != ('unbound', call_name(value)) for value in target[1].decorator_list)):
            return None
        bound = decorators == ['classmethod'] or not decorators and receiver[0] == 'receiver' and receiver[2]
        return 'function', target[1], bound

    def possible_sql_methods(self, node, seen=frozenset()):
        """Keep method origins when reassignment prevents a stable alias proof."""
        if node in seen:
            return frozenset()
        if not seen and node in self._possible_sql_methods:
            return self._possible_sql_methods[node]
        self.budget[0] -= 1
        if self.budget[0] < 0:
            raise SQLFlowLimit('SQL saved method resolution budget exceeded; analysis is incomplete')
        root = not seen
        seen = seen | {node}
        result = set()
        if isinstance(node, ast.Attribute) and node.attr in EXECUTE_METHODS | {'extra'}:
            result.add(node)
        elif isinstance(node, ast.Name):
            scope = self.sql_binding_cell(node.id, self.scope_of.get(node))
            owners = [scope] if scope is not None else []
            if node.id in self.indirect_rebindings:
                for candidate in self.owner_scopes.values():
                    self.budget[0] -= 1
                    if self.budget[0] < 0:
                        raise SQLFlowLimit('SQL saved method cell budget exceeded; analysis is incomplete')
                    if (node.id in candidate['capture_barriers']
                            and self.sql_binding_cell(node.id, candidate) is scope):
                        owners.append(candidate)
            for owner in owners:
                for candidate in owner['names'].get(node.id, ()):
                    if candidate and candidate[0] == 'alias':
                        result.update(self.possible_sql_methods(candidate[1], seen))
        result = frozenset(result)
        if root:
            self._possible_sql_methods[node] = result
        return result

    def closed_method_alias(self, method):
        """A local saved method keeps its receiver private until direct calls."""
        if method in self._closed_method_aliases:
            return self._closed_method_aliases[method]
        self._closed_method_aliases[method] = False
        owner = self.scope_of.get(method)
        if owner is None or not isinstance(owner['node'], (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        pending, visited = [method], set()
        while pending:
            value = pending.pop()
            if value in visited:
                continue
            visited.add(value)
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL saved receiver ownership budget exceeded; analysis is incomplete')
            parent = self.parents.get(value)
            if isinstance(parent, ast.Call) and parent.func is value:
                continue
            if not (isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is value):
                return False
            targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            for target in targets:
                if not isinstance(target, ast.Name) or self.lexical_owner(target) is not owner:
                    return False
                if owner['names'].get(target.id) != [('alias', value)]:
                    return False
                for reference in self.name_loads.get(target.id, ()):
                    if self.lexical_owner(reference) is not owner:
                        continue
                    scope = self.scope_of.get(reference)
                    while scope is not None and isinstance(scope['node'], (ast.ListComp, ast.SetComp, ast.DictComp)):
                        scope = scope['parent']
                    if scope is not owner:
                        return False
                    pending.append(reference)
        self._closed_method_aliases[method] = True
        return True

    def method_alias_references(self, value):
        parent = self.parents.get(value)
        if not (isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is value):
            return None
        targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
        if not all(isinstance(target, ast.Name) for target in targets):
            return None
        references = []
        for target in targets:
            owner = self.sql_binding_cell(target.id, self.scope_of.get(target))
            for reference in self.name_loads.get(target.id, ()):
                self.budget[0] -= 1
                if self.budget[0] < 0:
                    raise SQLFlowLimit('SQL saved method use budget exceeded; analysis is incomplete')
                if self.sql_binding_cell(reference.id, self.scope_of.get(reference)) is owner:
                    references.append(reference)
        return references

    def method_has_callable_use(self, method):
        """Distinguish callable raw/extra aliases from ordinary data fields."""
        pending, visited = [(method, ())], set()

        def parameter_reads(function, name, path):
            owner = self.owner_scopes[function]
            for reference in self.name_loads.get(name, ()):
                self.budget[0] -= 1
                if self.budget[0] < 0:
                    raise SQLFlowLimit('SQL callable-use budget exceeded; analysis is incomplete')
                if self.sql_binding_cell(name, self.scope_of.get(reference)) is owner:
                    pending.append((reference, path))

        while pending:
            value, path = pending.pop()
            identity = value, path
            if identity in visited:
                continue
            visited.add(identity)
            self.budget[0] -= 1
            if self.budget[0] < 0 or len(path) > 64:
                raise SQLFlowLimit('SQL callable-use budget exceeded; analysis is incomplete')
            parent = self.parents.get(value)
            if isinstance(parent, (ast.List, ast.Tuple)) and value in parent.elts:
                pending.append((parent, (('index', parent.elts.index(value), len(parent.elts)), *path)))
                continue
            if isinstance(parent, ast.Dict) and value in parent.values:
                key = parent.keys[parent.values.index(value)]
                selector = key.value if isinstance(key, ast.Constant) and isinstance(key.value, (str, int)) else None
                pending.append((parent, (('key', selector, None), *path)))
                continue
            if isinstance(parent, ast.Subscript) and parent.value is value and path:
                kind, selected, size = path[0]
                index = parent.slice
                actual = index.value if isinstance(index, ast.Constant) else None
                if (isinstance(index, ast.UnaryOp) and isinstance(index.op, ast.USub)
                        and isinstance(index.operand, ast.Constant) and type(index.operand.value) is int):
                    actual = -index.operand.value
                if kind == 'index' and type(actual) is int:
                    actual = actual + size if actual < 0 else actual
                if selected is None or actual is None or actual == selected:
                    pending.append((parent, path[1:]))
                continue
            if isinstance(parent, ast.Return):
                scope = self.scope_of.get(parent)
                function = scope['node'] if scope is not None else None
                if isinstance(function, ast.FunctionDef) and self.eager_function(function):
                    owner = scope['parent']
                    if (owner is not None and isinstance(owner['node'], ast.ClassDef)
                            and len(function.decorator_list) == 1
                            and self.resolve(function.decorator_list[0]) == ('unbound', 'property')):
                        for reference in self._sql_capability_candidates:
                            self.budget[0] -= 1
                            if self.budget[0] < 0:
                                raise SQLFlowLimit('SQL callable-property budget exceeded; analysis is incomplete')
                            if (isinstance(reference, ast.Attribute) and reference.attr == function.name
                                    and self.resolve(reference.value) == ('receiver', owner['node'], True)):
                                pending.append((reference, path))
                    for call in self.calls:
                        self.budget[0] -= 1
                        if self.budget[0] < 0:
                            raise SQLFlowLimit('SQL callable-return budget exceeded; analysis is incomplete')
                        target = self.resolve(call.func)
                        if target and target[0] == 'function' and target[1] is function:
                            pending.append((call, path))
                continue
            if isinstance(parent, ast.arguments):
                function = self.parents.get(parent)
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    parameters = [*parent.posonlyargs, *parent.args]
                    defaults = list(zip(parameters[len(parameters) - len(parent.defaults):], parent.defaults))
                    defaults.extend(zip(parent.kwonlyargs, parent.kw_defaults))
                    for parameter, default in defaults:
                        if default is value:
                            parameter_reads(function, parameter.arg, path)
                continue
            keyword = parent if isinstance(parent, ast.keyword) else None
            if keyword is not None:
                parent = self.parents.get(keyword)
            if isinstance(parent, ast.Call):
                if parent.func is value and not path:
                    return True
                if (parent.args and parent.args[0] is value
                        and not path and self.resolve(parent.func) in {('unbound', 'map'), ('unbound', 'filter')}):
                    return True
                target = self.resolve(parent.func)
                if (keyword is not None and keyword.arg == 'key' and not path
                        and target in {('unbound', 'min'), ('unbound', 'max'), ('unbound', 'sorted')}):
                    return True
                if target and target[0] == 'function':
                    parameters = _positional_parameters(target[1])[1 if target[2] else 0:]
                    if value in parent.args and parent.args.index(value) < len(parameters):
                        parameter_reads(target[1], parameters[parent.args.index(value)], path)
                    elif keyword is not None and keyword.arg in _all_parameters(target[1]):
                        parameter_reads(target[1], keyword.arg, path)
                # A SQL-shaped callback invocation differs from returning or
                # binding an ordinary raw/extra data field. Known SQL calls
                # keep their query/data slots; ordinary local helper proofs
                # also keep properties used only as data out of this path.
                data_builtin = (not self.dynamic_namespace and not self.builtin_namespace
                                and target is not None and target[0] == 'unbound'
                                and target[1] in {'print', 'str', 'format', 'repr', 'ascii'})
                if (parent.func is not value and not sql_sink_name(parent, self)
                        and not data_builtin and not self.non_database_callable(parent)):
                    others = [argument for argument in parent.args if argument is not value]
                    others += [item.value for item in parent.keywords if item is not keyword]
                    if (any(looks_like_sql(argument) for argument in others)
                            or any(item is not keyword and item.arg in {'where', 'select'}
                                   for item in parent.keywords)):
                        return True
            references = self.method_alias_references(value)
            if references is not None:
                pending.extend((reference, path) for reference in references)
        return False

    def escaped_sql_methods(self):
        """Locate unsupported transfers of selected SQL execution capabilities.

        Keep ordinary raw/extra properties out of the callable inventory.
        Known methods and lexical callable uses retain receiver checks; a
        capability exported through callbacks, containers or reflection must
        not silently disappear from file admission or literal-SQL proofs.
        """
        if self._escaped_sql_methods is not None:
            return self._escaped_sql_methods
        escaped = set()
        for node in self._sql_capability_candidates:
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL saved method inventory budget exceeded; analysis is incomplete')
            reflected = reflected_sql_name(node, self)
            if reflected:
                target = self.resolve(node.func)
                intrinsic = (target == ('unbound', 'getattr') or target in {
                    ('import', 'builtins.getattr'), ('import', 'operator.attrgetter'),
                    ('import', 'operator.methodcaller')})
                explicit_protocol = (isinstance(node.func, ast.Attribute)
                                     and node.func.attr in {'__getattribute__', '__getattr__'})
                if (intrinsic or explicit_protocol) and (reflected not in {'raw', 'extra'}
                                                        or self.method_has_callable_use(node)):
                    escaped.add(node)
                continue
            if (not isinstance(node, ast.Attribute) or not isinstance(node.ctx, ast.Load)
                    or node.attr not in EXECUTE_METHODS | {'extra'} or node in self.direct_callees):
                continue
            target = self.resolve(node)
            if (node.attr in {'raw', 'extra'} and not (target and target[0] == 'function')
                    and not self.method_has_callable_use(node)):
                continue
            probe = ast.Call(func=node, args=[], keywords=[])
            if self.non_database_callable(probe):
                continue
            pending, visited = [node], set()
            while pending:
                value = pending.pop()
                if value in visited:
                    continue
                visited.add(value)
                self.budget[0] -= 1
                if self.budget[0] < 0:
                    raise SQLFlowLimit('SQL saved method escape budget exceeded; analysis is incomplete')
                if isinstance(value, ast.Name):
                    if self.saved_non_sql_replacement(ast.Call(func=value, args=[], keywords=[])):
                        continue
                parent = self.parents.get(value)
                if isinstance(parent, ast.Call) and parent.func is value:
                    continue
                references = self.method_alias_references(value)
                if references is not None:
                    pending.extend(references)
                    continue
                # Eager argument/container evaluation can reach another SQL
                # sink before the opaque transfer. Refuse at that boundary,
                # after its children have contributed their known findings.
                if isinstance(parent, ast.keyword):
                    parent = self.parents.get(parent)
                if (isinstance(parent, ast.NamedExpr)
                        and isinstance(self.parents.get(parent), ast.Call)
                        and self.parents[parent].func is parent):
                    parent = self.parents[parent]
                escaped.add(parent if isinstance(parent, (ast.Call, ast.List, ast.Tuple, ast.Set,
                                                          ast.Dict, ast.Return, ast.Assign, ast.AnnAssign,
                                                          ast.arguments)) else value)
        owners = set()
        for node in escaped:
            scope = self.scope_of.get(node)
            while scope is not None:
                owners.add(scope['node'])
                scope = scope['parent']
        self.sql_method_escape_owners = frozenset(owners)
        self._escaped_sql_methods = frozenset(escaped)
        return self._escaped_sql_methods

    def covered_sql_facade_call(self, call, family):
        """A plain forwarding facade keeps every query at a modeled call site.

        This does not certify an arbitrary callback or a facade merely by its
        name. Every reference must remain a direct, recognized SQL call with
        one query argument. The forwarded value is that same parameter, or
        the sole variadic tuple inside a literal process argument vector.
        """
        key = call, family
        if key in self._sql_facade_call_coverage:
            return self._sql_facade_call_coverage[key]
        self._sql_facade_call_coverage[key] = False
        function = self.function_owner(call)
        if (family not in EXECUTE_METHODS or not isinstance(function, ast.FunctionDef)
                or function.name not in EXECUTE_METHODS or function.decorator_list
                or not self.eager_function(function) or function.args.kwarg
                or function.args.kwonlyargs or call.keywords or len(call.args) != 1):
            return False
        body = [statement for statement in function.body if not (
            isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str))]
        if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is not call:
            return False
        enclosing = self.owner_scopes[function]['parent']
        method = enclosing is not None and isinstance(enclosing['node'], ast.ClassDef)
        if method and self.class_escapes(enclosing['node']):
            return False
        parameters = _positional_parameters(function)[1 if method else 0:]
        argument = call.args[0]
        if len(parameters) == 1 and not function.args.vararg:
            if not isinstance(argument, ast.Name) or argument.id != parameters[0]:
                return False
        elif not parameters and function.args.vararg:
            if not isinstance(argument, (ast.List, ast.Tuple)):
                return False
            expansions = [value for value in argument.elts if isinstance(value, ast.Starred)]
            if (len(expansions) != 1 or not isinstance(expansions[0].value, ast.Name)
                    or expansions[0].value.id != function.args.vararg.arg
                    or any(not isinstance(value, (ast.Constant, ast.Starred)) for value in argument.elts)):
                return False
        else:
            return False
        references = [*self.name_loads.get(function.name, ()), *(
            value for value in self._sql_capability_candidates
            if isinstance(value, ast.Attribute) and value.attr == function.name)]
        for reference in references:
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL facade coverage budget exceeded; analysis is incomplete')
            target = self.resolve(reference)
            if (target and target[0] == 'function' and target[1] is function
                    and reference not in self.direct_callees):
                return False
        found = False
        for entry in self.calls:
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL facade coverage budget exceeded; analysis is incomplete')
            target = self.resolve(entry.func)
            if not (target and target[0] == 'function' and target[1] is function):
                continue
            if (sql_sink_name(entry, self) not in EXECUTE_METHODS or len(entry.args) != 1
                    or isinstance(entry.args[0], ast.Starred) or entry.keywords
                    or method and not target[2]):
                return False
            found = True
        self._sql_facade_call_coverage[key] = found
        return found

    def covered_sql_method_escape(self, node):
        """Retain capabilities in the inventory even when their uses are covered.

        Literal-scope admission must still see these operations. Only the
        execution refusal can defer to an existing SQL call boundary, and
        only for a plain, closed forwarding shape with no alternate exports.
        """
        if node in self._sql_escape_coverage:
            return self._sql_escape_coverage[node]
        self._sql_escape_coverage[node] = False
        parent = self.parents.get(node)
        if (isinstance(node, ast.Attribute) and node.attr in EXECUTE_METHODS | {'extra'}
                and isinstance(parent, ast.Attribute) and parent.value is node
                and parent.attr == '__code__' and isinstance(parent.ctx, ast.Store)):
            # Replacing function metadata does not export the bound callable.
            # The global member-write/dispatch invalidation remains in force.
            self._sql_escape_coverage[node] = True
            return True
        if (self.dynamic_namespace or self.builtin_namespace or self.reflective_member_writes
                or {'__code__', '__globals__', '__defaults__', '__kwdefaults__'} & self.member_writes):
            return False
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Attribute):
            function = self.function_owner(node)
            owner = self.owner_scopes.get(function, {}).get('parent')
            if (function is not None and owner is not None and isinstance(owner['node'], ast.ClassDef)
                    and function.name == node.value.attr and function.name in EXECUTE_METHODS
                    and function.body == [node] and len(function.decorator_list) == 1
                    and self.resolve(function.decorator_list[0]) == ('unbound', 'property')):
                # A property with the same SQL API name preserves the selected
                # argument family; its callers and saved aliases remain sinks.
                self._sql_escape_coverage[node] = True
                return True
        if (isinstance(node, ast.Call) and self.resolve(node.func) == ('unbound', 'getattr')
                and len(node.args) == 2 and not node.keywords
                and isinstance(parent, ast.Call) and parent.func is node
                and self.covered_sql_facade_call(parent, reflected_sql_name(node, self))):
            self._sql_escape_coverage[node] = True
            return True
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Attribute) and isinstance(node.value, ast.Attribute)
                and node.value.attr in EXECUTE_METHODS):
            return False
        field = node.targets[0]
        receiver = self.resolve(field.value)
        function = self.function_owner(node)
        class_field = (receiver and receiver[0] == 'receiver' and receiver[2]
                       and function is not None and function.name == '__init__'
                       and self.parents.get(node) is function and not self.class_escapes(receiver[1]))
        process_field = (receiver == ('import', 'subprocess') and function is None
                         and field.attr in {'run', 'call', 'check_output', 'check_call'}
                         and isinstance(self.parents.get(node), ast.Module))
        if not (class_field or process_field):
            return False
        found = False
        for value in self.scope_of:
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL stored callable coverage budget exceeded; analysis is incomplete')
            if process_field and isinstance(value, (ast.Name, ast.Attribute)) and self.resolve(value) == receiver:
                use = self.parents.get(value)
                if not (isinstance(use, ast.Attribute) and use.value is value and use.attr == field.attr):
                    return False
            if not (isinstance(value, ast.Attribute) and value.attr == field.attr
                    and self.resolve(value.value) == receiver):
                continue
            if value is field:
                continue
            use = self.parents.get(value)
            if (not isinstance(value.ctx, ast.Load) or not isinstance(use, ast.Call) or use.func is not value
                    or not self.covered_sql_facade_call(use, node.value.attr)):
                return False
            found = True
        self._sql_escape_coverage[node] = found
        return found

    def sql_binding_cell(self, name, scope):
        """Locate the declared lexical cell, including global/nonlocal writes."""
        key = name, scope['node'] if scope is not None else None
        if key not in self._sql_binding_cells:
            self._sql_binding_cells[key] = self._find_sql_binding_cell(name, scope)
        return self._sql_binding_cells[key]

    def _find_sql_binding_cell(self, name, scope):
        while scope is not None:
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL alias cell budget exceeded; analysis is incomplete')
            if name in scope['capture_barriers']:
                nonlocal_cell = name in scope['nonlocal_names']
                scope = scope['parent']
                while scope is not None and (isinstance(scope['node'], ast.ClassDef)
                                             or not nonlocal_cell and not isinstance(scope['node'], ast.Module)):
                    scope = scope['parent']
                continue
            if name in scope['names'] or isinstance(scope['node'], ast.Module):
                return scope
            child = scope['node']
            scope = scope['parent']
            if not isinstance(child, ast.ClassDef):
                while scope and isinstance(scope['node'], ast.ClassDef):
                    scope = scope['parent']
        return None

    def unresolved_sql_aliases(self, call):
        possible = frozenset(name.rsplit('.', 1)[-1] for name in self.possible_sql_imports(call.func)
                             if name.rsplit('.', 1)[-1] in EXECUTE_METHODS | {'extra'})
        methods = (self.possible_sql_methods(call.func) if isinstance(call.func, ast.Name) else frozenset())
        possible |= frozenset(method.attr for method in methods)
        if not possible:
            return possible
        target = self.resolve(call.func)
        if target and target[0] == 'import':
            return frozenset()
        saved = self.saved_sql_method(call.func) if methods else None
        if saved is not None and self.saved_method_capture_is_stable(saved):
            return frozenset()
        if methods and self.saved_non_sql_replacement(call):
            return frozenset()
        return possible

    def plain_alias_replacement(self, call):
        """A final direct definition can replace an import without dispatch.

        This deliberately recognizes only returning an argument, a constant,
        or an argument's builtin length. The caller must prove the latter's
        actual object shape; a custom __len__ would still be opaque execution.
        """
        if (not isinstance(call.func, ast.Name) or self.dynamic_namespace or self.builtin_namespace
                or self.reflective_member_writes or {'__code__', '__globals__'} & self.member_writes):
            return None
        scope = self.lexical_owner(call.func)
        if scope is None or isinstance(scope['node'], ast.ClassDef):
            return None
        candidates = scope['names'].get(call.func.id, ())
        target = candidates[-1] if candidates else None
        if not target or target[0] != 'function':
            return None
        function = target[1]
        if (not isinstance(function, ast.FunctionDef) or function.decorator_list
                or self.parents.get(function) is not scope['node']
                or function.end_lineno >= call.lineno):
            return None
        for reference in self.name_loads.get(call.func.id, ()):
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL alias ownership budget exceeded; analysis is incomplete')
            if self.lexical_owner(reference) is scope and reference not in self.direct_callees:
                return None
        body = [statement for statement in function.body if not (
            isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str))]
        if len(body) != 1 or not isinstance(body[0], ast.Return):
            return None
        value = body[0].value
        if value is None or isinstance(value, ast.Constant):
            return function, None
        if isinstance(value, ast.Name) and value.id in _all_parameters(function):
            return function, None
        if (isinstance(value, ast.Call) and self.resolve(value.func) == ('unbound', 'len')
                and len(value.args) == 1 and not value.keywords and isinstance(value.args[0], ast.Name)
                and value.args[0].id in _all_parameters(function)):
            return function, value.args[0].id
        return None

    def closed_local_callable(self, function, active=frozenset()):
        """Follow direct uses and exact identity wrappers, refusing exports."""
        if function in self._closed_function_cache:
            return self._closed_function_cache[function]
        if function in active or not isinstance(function, ast.FunctionDef) or function.decorator_list:
            return False
        active = active | {function}
        owner = self.owner_scopes[function]['parent']
        if owner is None or isinstance(owner['node'], ast.ClassDef):
            return False  # a class attribute needs its owner's separate escape proof
        pending, seen, calls = [(owner, function.name)], set(), set()
        while pending:
            scope, name = pending.pop()
            key = scope['node'], name
            if key in seen:
                continue
            seen.add(key)
            if name in self.indirect_rebindings or len(scope['names'].get(name, ())) != 1:
                return False
            for reference in self.name_loads.get(name, ()):
                self.budget[0] -= 1
                if self.budget[0] < 0:
                    raise SQLFlowLimit('SQL callable ownership budget exceeded; analysis is incomplete')
                if self.lexical_owner(reference) is not scope:
                    continue
                value, parent = reference, self.parents.get(reference)
                while isinstance(parent, ast.Call) and parent.func is not value:
                    target = self.resolve(parent.func)
                    if (parent.args != [value] or parent.keywords or not target
                            or target[0] != 'function' or target[2]):
                        return False
                    wrapper = target[1]
                    args = wrapper.args
                    positional = args.posonlyargs + args.args
                    body = [statement for statement in wrapper.body if not (
                        isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
                        and isinstance(statement.value.value, str))]
                    if (len(positional) != 1 or args.vararg or args.kwarg or args.kwonlyargs or args.defaults
                            or len(body) != 1 or not isinstance(body[0], ast.Return)
                            or not isinstance(body[0].value, ast.Name)
                            or body[0].value.id != positional[0].arg
                            or not self.closed_local_callable(wrapper, active)):
                        return False
                    value, parent = parent, self.parents.get(parent)
                if isinstance(parent, ast.Call) and parent.func is value:
                    calls.add(parent)
                    continue
                if (isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is value
                        and self.parents.get(parent) is self.scope_of[parent]['node']):
                    targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                    if all(isinstance(target, ast.Name) for target in targets):
                        pending.extend((self.scope_of[parent], target.id) for target in targets)
                        continue
                return False
        self._closed_function_cache[function] = True
        self._closed_function_calls[function] = frozenset(calls)
        return True

    def process_call(self, call, target):
        """A closed stdlib process launcher does not consume Python SQL text."""
        consumers = {'subprocess.run', 'subprocess.call', 'subprocess.check_call', 'subprocess.check_output'}
        if (not target or target[0] != 'import' or target[1] not in consumers
                or len(call.args) != 1 or isinstance(call.args[0], ast.Starred)
                or any(keyword.arg in {None, 'preexec_fn'} for keyword in call.keywords)):
            return False
        for keyword in call.keywords:
            if keyword.arg in {'stdin', 'stdout', 'stderr'} and not (
                    isinstance(keyword.value, ast.Constant)
                    and type(keyword.value.value) in {int, type(None)}):
                return False  # file objects can execute arbitrary code through fileno()
        if self._process_namespace_closed is None:
            closed = (not self.dynamic_namespace and not self.builtin_namespace
                      and not self.regex_namespace_escape and not self.reflective_member_writes
                      and not {'__code__', '__globals__'} & self.member_writes)
            imports = {name for scope in self.owner_scopes.values() for name, values in scope['names'].items()
                       for value in values if value and value[0] == 'import'
                       and (value[1] == 'subprocess' or value[1].startswith('subprocess.'))}
            for name in imports:
                for reference in self.name_loads.get(name, ()):
                    self.budget[0] -= 1
                    if self.budget[0] < 0:
                        raise SQLFlowLimit('SQL process binding budget exceeded; analysis is incomplete')
                    resolved = self.resolve(reference)
                    if not resolved or resolved[0] != 'import' or not (
                            resolved[1] == 'subprocess' or resolved[1].startswith('subprocess.')):
                        continue
                    value, parent = reference, self.parents.get(reference)
                    while isinstance(parent, ast.Attribute) and parent.value is value:
                        if not isinstance(parent.ctx, ast.Load) or parent.attr.startswith('_'):
                            closed = False
                        value, parent = parent, self.parents.get(parent)
                    selected = self.resolve(value)
                    if (value not in self.direct_callees or not selected or selected[0] != 'import'
                            or selected[1] not in consumers):
                        closed = False
            self._process_namespace_closed = closed
        return self._process_namespace_closed

    def primitive_process_argument(self, value, seen=frozenset(), *, immutable=False, parameters=frozenset()):
        """Reject path/file protocol objects at a process wrapper's call site."""
        self.budget[0] -= 1
        if self.budget[0] < 0:
            raise SQLFlowLimit('SQL process argument budget exceeded; analysis is incomplete')
        if value in seen:
            return False
        seen = seen | {value}
        if isinstance(value, ast.Constant):
            return type(value.value) in {str, bytes, int, float, bool, type(None)}
        if isinstance(value, (ast.Tuple, ast.List)):
            if immutable and isinstance(value, ast.List):
                return False
            return all(self.primitive_process_argument(item, seen, immutable=True, parameters=parameters)
                       for item in value.elts)
        if isinstance(value, ast.Starred):
            return self.primitive_process_argument(value.value, seen, parameters=parameters)
        if isinstance(value, ast.JoinedStr):
            return (len(value.values) != 1 or isinstance(value.values[0], ast.Constant)
                    or isinstance(value.values[0], ast.FormattedValue)
                    and self.primitive_process_argument(value.values[0].value, seen, parameters=parameters))
        if not isinstance(value, ast.Name):
            return False
        scope = self.lexical_owner(value)
        if scope is None or len(scope['names'].get(value.id, ())) != 1:
            return False
        if (scope['node'], value.id) in parameters:
            # This hypothesis is used only for a closed log writer. Every
            # direct/alias/identity invocation must independently prove its
            # actual inputs primitive before the certificate is accepted.
            return True
        assignment = self.literal_assignments.get((scope['node'], value.id))
        if assignment is not None:
            if assignment.lineno >= value.lineno:
                return False
            if isinstance(assignment.value, ast.List):
                if immutable:
                    return False  # iteration can export and mutate a mutable child
                targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
                if len(targets) != 1:
                    return False
            for reference in self.name_loads.get(value.id, ()):
                if self.lexical_owner(reference) is not scope:
                    continue
                enclosing = self.scope_of[reference]
                while enclosing is not scope:
                    if isinstance(enclosing['node'], (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                        if not self.closed_local_callable(enclosing['node']):
                            return False
                    enclosing = enclosing['parent']
                if isinstance(assignment.value, ast.List):
                    parent = self.parents.get(reference)
                    if (isinstance(parent, (ast.comprehension, ast.For)) and parent.iter is reference):
                        continue
                    if (isinstance(parent, ast.Compare) and len(parent.ops) == 1
                            and isinstance(parent.ops[0], (ast.In, ast.NotIn))
                            and parent.comparators == [reference]):
                        continue
                    return False
            return self.primitive_process_argument(assignment.value, seen, immutable=immutable, parameters=parameters)
        if isinstance(scope['node'], (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for generator in scope['node'].generators:
                if value.id in binding_target_names(generator.target) and not generator.is_async:
                    return self.primitive_process_argument(generator.iter, seen, parameters=parameters)
        return False

    def primitive_instrumentation_writer(self, call, function, roots):
        """An emptied log cannot release opaque objects or forward SQL text."""
        scope = self.lexical_owner(call.func.value)
        if (scope is None or not isinstance(scope['node'], ast.FunctionDef)
                or self.owner_scopes[function]['parent'] is not scope):
            return False
        parameters = frozenset((function, name) for name in roots
                               if function.args.kwarg is None or name != function.args.kwarg.arg)
        for reference in self.name_loads.get(call.func.value.id, ()):
            if self.lexical_owner(reference) is not scope:
                continue
            member = self.parents.get(reference)
            use = self.parents.get(member)
            if (isinstance(member, ast.Attribute) and member.attr == 'append'
                    and isinstance(use, ast.Call) and use.func is member):
                if (self.scope_of[use] is not self.owner_scopes[function]
                        or not self.primitive_process_argument(use.args[0], immutable=True, parameters=parameters)):
                    # Another writer, an opaque conversion, or a deferred
                    # append has no primitive-content ownership proof here.
                    return False
        return True

    def primitive_instrumentation_calls(self, function, call):
        defaults = [*function.args.defaults, *(value for value in function.args.kw_defaults if value is not None)]
        if not all(self.primitive_process_argument(value, immutable=True) for value in defaults):
            return False
        calls = self._closed_function_calls.get(function, frozenset()) | {call}
        return all(all(self.primitive_process_argument(value.value) if isinstance(value, ast.Starred)
                       else self.primitive_process_argument(value, immutable=True) for value in invocation.args)
                   and all(keyword.arg is not None and self.primitive_process_argument(keyword.value, immutable=True)
                           for keyword in invocation.keywords) for invocation in calls)

    def cleared_list_iteration(self, reference, scope):
        """A direct builtin predicate sees the list just unconditionally cleared."""
        loop = self.parents.get(reference)
        generator = self.parents.get(loop)
        consumer = self.parents.get(generator)
        if (not isinstance(loop, ast.comprehension) or loop.iter is not reference
                or not isinstance(generator, ast.GeneratorExp) or generator.generators != [loop]
                or loop.is_async or loop.ifs or not isinstance(consumer, ast.Call)
                or consumer.args != [generator] or consumer.keywords
                or self.resolve(consumer.func) not in {('unbound', 'any'), ('unbound', 'all')}):
            return False
        statement = consumer
        while statement in self.parents and self.parents[statement] is not scope['node']:
            statement = self.parents[statement]
        body = scope['node'].body
        if statement not in body or body.index(statement) == 0:
            return False
        previous = body[body.index(statement) - 1]
        call = previous.value if isinstance(previous, ast.Expr) else None
        if (not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute)
                or call.func.attr != 'clear' or call.args or call.keywords
                or not isinstance(call.func.value, ast.Name) or call.func.value.id != reference.id
                or self.lexical_owner(call.func.value) is not scope):
            return False
        return not any(isinstance(node, (ast.Call, ast.NamedExpr, ast.Await, ast.Yield, ast.YieldFrom))
                       and node is not consumer for node in ast.walk(statement))

    def instrumentation_append(self, call):
        """Recognize a closed builtin list used only to append, clear and count.

        The retained arguments cannot flow to an opaque reader. The sole
        contents-read extension is a predicate over a freshly cleared list;
        no callback in its generator body can actually run on that path.
        """
        if (not isinstance(call.func, ast.Attribute) or call.func.attr != 'append'
                or not isinstance(call.func.value, ast.Name) or len(call.args) != 1 or call.keywords
                or isinstance(call.args[0], ast.Starred)):
            return False
        reference = call.func.value
        scope = self.lexical_owner(reference)
        if scope is None:
            return False
        key = scope['node'], reference.id
        if key in self._instrumentation_lists:
            return self._instrumentation_lists[key]
        assignment = self.literal_assignments.get(key)
        if (len(scope['names'].get(reference.id, ())) != 1 or assignment is None
                or not isinstance(assignment.value, ast.List) or assignment.value.elts
                or assignment.lineno >= call.lineno):
            return False
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name) or targets[0].id != reference.id:
            return False
        for value in self.name_loads.get(reference.id, ()):
            self.budget[0] -= 1
            if self.budget[0] < 0:
                raise SQLFlowLimit('SQL instrumentation ownership budget exceeded; analysis is incomplete')
            if self.lexical_owner(value) is not scope:
                continue
            enclosing = self.scope_of[value]
            while enclosing is not scope:
                if isinstance(enclosing['node'], (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    if not self.closed_local_callable(enclosing['node']):
                        return False
                enclosing = enclosing['parent']
            parent = self.parents.get(value)
            if isinstance(parent, ast.Attribute) and parent.value is value:
                use = self.parents.get(parent)
                if (isinstance(use, ast.Call) and use.func is parent and not use.keywords
                        and ((parent.attr == 'append' and len(use.args) == 1
                              and not isinstance(use.args[0], ast.Starred))
                             or parent.attr == 'clear' and not use.args)):
                    continue
            if (isinstance(parent, ast.Call) and parent.args == [value] and not parent.keywords
                    and self.resolve(parent.func) == ('unbound', 'len')):
                continue
            if self.cleared_list_iteration(value, scope):
                continue
            return False
        self._instrumentation_lists[key] = True
        return True

    def forwards_to_unknown(self, function, bound):
        """Refuse a non-SQL certificate when the SQL slot escapes to a callback.

        Follow parameter/alias text through local helper parameters, including
        record fields. Field selection needs its own provenance proof before
        forwarding to an opaque callback can be certified non-SQL.
        """
        cache_key = function, bound
        if cache_key in self._forwarding_cache:
            return self._forwarding_cache[cache_key]
        parameters = _positional_parameters(function)[1 if bound else 0:]
        roots = set(parameters[:1])
        roots.update(argument.arg for argument in function.args.kwonlyargs)
        if function.args.vararg:
            roots.add(function.args.vararg.arg)
        if function.args.kwarg:
            roots.add(function.args.kwarg.arg)
        if not roots:
            return True
        pending, seen = [(function, frozenset(roots))], set()
        while pending:
            current, names = pending.pop()
            key = current, names
            if key in seen:
                continue
            seen.add(key)
            names = set(names)
            callable_names = set()

            def carries_text(value):
                self.budget[0] -= 1
                if self.budget[0] < 0:
                    raise SQLFlowLimit('SQL forwarding budget exceeded; analysis is incomplete')
                if isinstance(value, ast.Name):
                    return value.id in names
                if isinstance(value, ast.Attribute):
                    return carries_text(value.value)
                if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
                    if carries_text(value.func.value):
                        return True
                return any(carries_text(child) for child in ast.iter_child_nodes(value))

            def carries_callable(value):
                self.budget[0] -= 1
                if self.budget[0] < 0:
                    raise SQLFlowLimit('SQL callable forwarding budget exceeded; analysis is incomplete')
                if isinstance(value, ast.Name):
                    return value.id in callable_names
                if isinstance(value, ast.Attribute):
                    return carries_text(value.value) or carries_callable(value.value)
                if isinstance(value, (ast.Subscript, ast.List, ast.Tuple, ast.Set, ast.Dict, ast.IfExp, ast.BoolOp)):
                    return any(carries_callable(child) for child in ast.iter_child_nodes(value))
                return False

            def exports_callable(value):
                if isinstance(value, ast.Name):
                    return value.id in callable_names
                if isinstance(value, ast.Attribute):
                    return (exports_callable(value.value)
                            or carries_text(value.value) and callable(getattr(str, value.attr, None)))
                if isinstance(value, (ast.Subscript, ast.List, ast.Tuple, ast.Set, ast.Dict, ast.IfExp, ast.BoolOp)):
                    return any(exports_callable(child) for child in ast.iter_child_nodes(value))
                return False

            changed = True
            while changed:
                changed = False
                for statement in ast.walk(current):
                    if (statement is not current
                            and isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
                            and any(isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
                                    and child.id in names for child in ast.walk(statement))):
                        return True
                    if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
                        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                        heap_target = any(isinstance(child, (ast.Attribute, ast.Subscript))
                                          for target in targets for child in ast.walk(target))
                        if carries_text(statement.value):
                            if heap_target:
                                # Wrapping or transforming the SQL slot before
                                # storing it does not make receiver state safe.
                                # Without heap alias/return summaries a later
                                # callback may recover exactly that text.
                                return True
                            added = {name for target in targets for name in binding_target_names(target)} - names
                            names.update(added)
                            changed |= bool(added)
                        if carries_callable(statement.value):
                            if heap_target:
                                return True
                            added = {name for target in targets for name in binding_target_names(target)} - callable_names
                            callable_names.update(added)
                            changed |= bool(added)
                    elif isinstance(statement, (ast.NamedExpr, ast.AugAssign)) and carries_text(statement.value):
                        if any(isinstance(child, (ast.Attribute, ast.Subscript)) for child in ast.walk(statement.target)):
                            return True
                        added = set(binding_target_names(statement.target)) - names
                        names.update(added)
                        changed |= bool(added)
                    elif isinstance(statement, (ast.For, ast.AsyncFor, ast.comprehension)) and carries_text(statement.iter):
                        if any(isinstance(child, (ast.Attribute, ast.Subscript)) for child in ast.walk(statement.target)):
                            return True
                        added = set(binding_target_names(statement.target)) - names
                        names.update(added)
                        changed |= bool(added)
            for call in self._function_calls.get(current, ()):
                if (any(isinstance(child, ast.Name) and child.id in callable_names for child in ast.walk(call.func))
                        or any(exports_callable(value) for value in [*call.args, *(kw.value for kw in call.keywords)])):
                    # An extracted string method remains a callable even
                    # though an ordinary record field is not raw SQL text.
                    # Invoking or exporting that alias requires effects the
                    # local non-database certificate does not model.
                    return True
                positional = [index for index, value in enumerate(call.args) if carries_text(value)]
                keywords = {kw.arg for kw in call.keywords if carries_text(kw.value)}
                if not positional and not keywords:
                    continue
                target = self.resolve(call.func)
                if self.process_call(call, target):
                    self._process_forwarders.add(function)
                    continue
                if (current is function and self.instrumentation_append(call)
                        and self.primitive_instrumentation_writer(call, function, roots)):
                    self._instrumentation_forwarders.add(function)
                    continue
                if target and target[0] == 'function':
                    if target[1].args.vararg or target[1].args.kwarg:
                        return True
                    owner = self.owner_scopes[target[1]]['parent']
                    if (owner is None or (self.class_escapes(owner['node'])
                            if isinstance(owner['node'], ast.ClassDef) else not self.closed_local_callable(target[1]))):
                        return True
                    params = _positional_parameters(target[1])[1 if target[2] else 0:]
                    selected = {params[index] for index in positional if index < len(params)}
                    selected.update(name for name in keywords if name in _all_parameters(target[1]))
                    if any(isinstance(value, ast.Starred) for value in call.args) or None in keywords:
                        return True
                    if selected:
                        pending.append((target[1], frozenset(selected)))
                    continue
                if target and target[0] == 'class':
                    owner = target[1]
                    if owner.bases or owner.keywords:
                        return True
                    for decorator in owner.decorator_list:
                        expression = decorator.func if isinstance(decorator, ast.Call) else decorator
                        if self.resolve(expression) != ('import', 'dataclasses.dataclass'):
                            return True
                    if any(isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) for statement in owner.body):
                        return True
                    continue
                if (target and target[0] == 'unbound' and target[1] in {
                        'str', 'bytes', 'bytearray', 'len', 'int', 'float', 'bool', 'repr', 'format',
                        'list', 'tuple', 'set', 'frozenset', 'dict'}):
                    continue
                return True
        self._forwarding_cache[cache_key] = False
        return False

    def non_database_callable(self, call):
        if (self.dynamic_namespace or self.builtin_namespace or self.reflective_member_writes
                or {'__code__', '__globals__', '__defaults__', '__kwdefaults__'} & self.member_writes):
            return False
        target = self.resolve(call.func)
        saved = self.saved_sql_method(call.func) if isinstance(call.func, ast.Name) else None
        if saved is not None:
            target = self.captured_method_target(saved) or target
        if not target or target[0] != 'function':
            return False
        owner = self.owner_scopes[target[1]]['parent']
        if owner is None:
            return False
        if isinstance(owner['node'], ast.ClassDef):
            if ({'__getattribute__', '__getattr__'} & owner['names'].keys()
                    or '__class__' in self.member_writes or self.class_escapes(owner['node'], saved)):
                return False
        elif target[1].decorator_list or not self.closed_local_callable(target[1]):
            return False
        if target[1] in self.local_sql_effects() or self.forwards_to_unknown(target[1], target[2]):
            return False
        if (target[1] in self._instrumentation_forwarders
                and not self.primitive_instrumentation_calls(target[1], call)):
            return False
        if target[1] in self._process_forwarders:
            return all(self.primitive_process_argument(value) for value in
                       [*call.args, *(keyword.value for keyword in call.keywords)])
        return True

    def _scope(self, node, parent):
        scope = {'node': node, 'parent': parent, 'names': {}, 'capture_barriers': set(),
                 'nonlocal_names': set(), 'references': set(), 'reflective': False}
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
        if isinstance(node, ast.Attribute):
            scope['references'].add(node.attr)
            scope['reflective'] |= node.attr in REFLECTIVE_LOOKUPS
            if isinstance(node.ctx, ast.Load) and node.attr in EXECUTE_METHODS | {'extra'}:
                self._sql_capability_candidates.append(node)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            scope['references'].add(node.value)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            scope['references'].add(node.id)
            if node.id == 'getattr':
                parent = self.parents.get(node)
                # A direct literal selector names the only extra body it
                # can reach. Its string is already in the reference index.
                # Aliases and computed selectors still require full flow.
                static_selector = (isinstance(parent, ast.Call) and parent.func is node
                                   and len(parent.args) in {2, 3} and not parent.keywords
                                   and not any(isinstance(arg, ast.Starred) for arg in parent.args)
                                   and isinstance(parent.args[1], ast.Constant)
                                   and isinstance(parent.args[1].value, str)
                                   and parent.args[1].value not in REFLECTIVE_LOOKUPS)
                scope['reflective'] |= not static_selector
            else:
                scope['reflective'] |= node.id in REFLECTIVE_LOOKUPS
        # These edges belong to the same charged binding-index pass. Reuse
        # them for import escape proofs instead of walking the entire file
        # again whenever the first regular-expression shape is requested.
        self.parents.update((child, node) for child in ast.iter_child_nodes(node))
        if (isinstance(node, ast.ImportFrom) and node.module in {'sys', 'importlib'}
                and any(alias.name in {'modules', 'import_module'} for alias in node.names)):
            self.regex_namespace_escape = True
        if (isinstance(node, ast.Attribute) and node.attr in {
                '_getframe', 'currentframe', 'f_globals', 'f_locals', 'f_builtins',
                '__globals__', '__self__',
                '__getattribute__', '__getattr__', 'attrgetter', 'methodcaller'}
                or isinstance(node, ast.ImportFrom) and
                (node.module == 'sys' and any(alias.name == '_getframe' for alias in node.names)
                 or node.module == 'inspect' and any(alias.name in {'currentframe', 'getouterframes', 'stack'}
                                                    for alias in node.names)
                 or node.module == 'operator' and any(alias.name in {'attrgetter', 'methodcaller'}
                                                     for alias in node.names))
                or isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == 'getattr' and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant) and node.args[1].value in {
                    '_getframe', 'currentframe', 'f_globals', 'f_locals', 'f_builtins',
                    '__globals__', '__self__'}):
            # Frame dictionaries and reflective attribute factories can
            # replace globals, fast locals and builtin callables without a
            # Name(Store) or an explicit builtins import. Function globals
            # and builtin callable owners expose the same mutable authority.
            # Neither a validator binding nor a builtin return shape remains
            # proved when this capability escapes ordinary lexical tracking.
            self.dynamic_namespace = True
            self.builtin_namespace = True
        if (isinstance(node, ast.Name) and node.id in {'__builtins__', '__import__', 'vars'}
                or isinstance(node, ast.Attribute) and node.attr in {'__builtins__', '__dict__', 'modules', 'import_module'}
                or isinstance(node, ast.Import) and any(alias.name == 'builtins' for alias in node.names)
                or isinstance(node, ast.ImportFrom) and node.module == 'builtins'):
            # Access to the mutable builtin namespace invalidates builtin
            # return-shape proofs, even without a lexical Name(Store).
            self.builtin_namespace = True
        if isinstance(node, ast.Name) and node.id in {'locals', 'globals', 'vars', 'exec', 'eval'}:
            enclosing = scope
            while enclosing is not None:
                self.budget[0] -= 1
                if self.budget[0] < 0:
                    raise SQLFlowLimit('SQL binding budget exceeded; analysis is incomplete')
                enclosing['capture_barriers'].add('*')
                enclosing = enclosing['parent']
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            self.name_loads.setdefault(node.id, []).append(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if getattr(node, 'name', None) in {'__hash__', '__eq__', '__index__'}:
                self.key_callbacks.add(node)
            if getattr(node, 'name', None) in {
                    '__bool__', '__len__', '__contains__', '__eq__', '__ne__',
                    '__lt__', '__le__', '__gt__', '__ge__'}:
                self.predicate_callbacks.add(node)
            self.parents.update((child, node.args) for child in ast.iter_child_nodes(node.args))
            for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                             *([node.args.vararg] if node.args.vararg else []),
                             *([node.args.kwarg] if node.args.kwarg else [])]:
                self.parents.update((child, argument) for child in ast.iter_child_nodes(argument))
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
                self.parents.update((child, generator) for child in ast.iter_child_nodes(generator))
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
            scope['capture_barriers'].update(node.names)
            if isinstance(node, ast.Nonlocal):
                scope['nonlocal_names'].update(node.names)
        if (isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None
                and self.parents.get(node) is scope['node']):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    self.literal_assignments[(scope['node'], target.id)] = node
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
            if isinstance(node, ast.ImportFrom) and node.module:
                scope['reflective'] |= bool(REFLECTIVE_LOOKUPS.intersection(node.module.split('.')))
            for alias in node.names:
                # Keep the imported capability even when its local spelling
                # hides a reflective lookup, e.g. attrgetter as select.
                scope['reflective'] |= bool(REFLECTIVE_LOOKUPS.intersection(alias.name.split('.')))
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
        if type(node).__name__ == 'MatchMapping' and node.rest:
            self._bind(scope, node.rest, None)
        if isinstance(node, ast.Call):
            self.calls.append(node)
            self.direct_callees.add(node.func)
            if any(isinstance(argument, ast.Constant) and isinstance(argument.value, str)
                   and argument.value in EXECUTE_METHODS | {'extra'} for argument in node.args[:2]):
                self._sql_capability_candidates.append(node)
        if isinstance(node, ast.NamedExpr):
            target_scope = scope
            while isinstance(target_scope['node'], (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                target_scope = target_scope['parent']
            self._walk(node.target, target_scope)
            self._walk(node.value, scope)
            return
        for child in ast.iter_child_nodes(node):
            # Operator and context markers are field tags, with no lexical
            # bindings, references or descendants. Their owning expressions
            # retain the tags; indexing shared singleton leaves adds no facts.
            if isinstance(child, (ast.expr_context, ast.operator, ast.unaryop,
                                  ast.boolop, ast.cmpop)):
                continue
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
        root = seen is None
        if root and node in self._binding_resolutions:
            return self._binding_resolutions[node]
        result = self._resolve(node, seen)
        # Nested alias-cycle queries have context-dependent visited sets.
        # Only a complete root result belongs to the immutable lexical index.
        if root:
            self._binding_resolutions[node] = result
        return result

    def _resolve(self, node, seen=None):
        self.budget[0] -= 1
        if self.budget[0] < 0:
            raise SQLFlowLimit('SQL binding resolution budget exceeded; analysis is incomplete')
        seen = set() if seen is None else seen
        if node in seen:
            return None
        seen.add(node)
        if isinstance(node, ast.Name):
            target = self.lookup(node.id, self.scope_of.get(node), seen)
            return self.constructed_receiver(node) if target is None else target
        if not isinstance(node, ast.Attribute) or node.attr in self.member_writes:
            return None
        parent = self.resolve(node.value, seen)
        if not parent:
            return None
        if parent[0] == 'import':
            return ('import', parent[1] + '.' + node.attr)
        if parent == ('unbound', 'dict') and node.attr == 'fromkeys':
            return ('unbound', 'dict.fromkeys')
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


def reflected_sql_name(node, bindings=None):
    if not isinstance(node, ast.Call):
        return ''
    short = call_name(node.func).rsplit('.', 1)[-1]
    if bindings is not None:
        target = bindings.resolve(node.func)
        if target == ('unbound', 'getattr'):
            short = 'getattr'
        elif target and target[0] == 'import' and target[1] in {
                'builtins.getattr', 'operator.attrgetter', 'operator.methodcaller'}:
            short = target[1].rsplit('.', 1)[-1]
    position = 1 if short == 'getattr' else 0 if short in {
        '__getattribute__', '__getattr__', 'attrgetter', 'methodcaller'} else None
    if position is not None and len(node.args) > position:
        name = node.args[position]
        if (isinstance(name, ast.Constant) and isinstance(name.value, str)
                and name.value in EXECUTE_METHODS | {'extra'}):
            return name.value
    return ''


def sql_sink_name(node, bindings=None):
    """Share the modeled sink families between admission and argument binding."""
    short = call_name(node.func).rsplit('.', 1)[-1]
    if bindings is not None:
        if isinstance(node.func, ast.Name):
            saved = bindings.saved_sql_method(node.func)
            if saved is not None:
                short = saved.attr
        if (short not in EXECUTE_METHODS | {'extra'} and not any(
                name.rsplit('.', 1)[-1] in EXECUTE_METHODS | {'extra'}
                for name in bindings.possible_sql_imports(node.func))
                and not bindings.possible_sql_methods(node.func)):
            return ''
        target = bindings.resolve(node.func)
        if target and target[0] == 'import':
            canonical = target[1].rsplit('.', 1)[-1]
            if canonical in EXECUTE_METHODS | {'extra'}:
                # Import aliases and stable local aliases retain the imported
                # API's SQL slot. A bare spelling cannot establish this link:
                # lexical shadowing or reassignment makes resolve refuse it.
                short = canonical
        elif bindings.unresolved_sql_aliases(node):
            # Once an imported callable's identity is ambiguous, its old
            # query/params contract is no longer a proven execution boundary.
            # The visitor keeps all argument SQL facts and refuses explicitly.
            return ''
    if short in EXECUTE_METHODS | {'extra'} and bindings is not None and bindings.non_database_callable(node):
        return ''
    return short if short in EXECUTE_METHODS or short == 'extra' else ''


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


def looks_like_sql(node):
    # Only literal text supplies SQL syntax. Identifiers such as ``call`` or
    # ``update`` (including arithmetic like start + call.end()) are values,
    # not SQL keywords. Aliased templates retain their ordinary flow facts.
    return bool(SQL_RE.search(' '.join(string_parts(node))))


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


class SQLFlowLimit(AnalysisLimit, RuntimeError):
    """The bounded SQL pass could not establish a complete result."""

    def __init__(self, message, *, components=()):
        super().__init__(message)
        self.components = tuple(components)


class SQLNoNormalReturn(Exception):
    """Internal bottom edge while solving a recursive return summary."""


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
    # its one caller passes the source text and lines, parameter names and risk, sanitizer facts, step limit, budget and bindings; a parameter record is bead ultimate_bug_scanner-8tqg — ubs:ignore[py.functions.high-param-count]
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
        self.value_kinds = {}
        # A list can be updated without heap-alias summaries only while its
        # local binding owns the object. Copies/escapes revoke this proof.
        self.exclusive_lists = set()
        self.deferred_list_captures = set()
        self.binding_sites = {}
        self._binding_site = None
        self._sink_risks = {}
        self._suppression_index = None
        self._literal_statement_scopes = None
        self._sql_callable_escape_sites = None
        self.remaining_steps = max_steps
        self._budget = [max_steps] if budget is None else budget
        self._pending_raise = None
        # A loaded expression denotes its value *at evaluation time*. Later
        # argument/walrus writes must not change a value already captured by
        # a tuple, SQL call or bound format method. AST objects (not their
        # recycled numeric ids) key these bounded per-analysis snapshots.
        self._evaluated_values = {}
        self._evaluated_call_targets = {}
        self._evaluated_comparison_truths = {}
        self._indexed_receivers = {}
        # Generator objects carry identity, not their future yielded value.
        # Aliases share the fresh/exhausted state, including across branches.
        self.generator_bindings = {}
        self.generator_phases = {}
        self._generator_specs = {}
        self._generator_running = set()
        self._generator_scope = ()
        self._short_circuiting = False
        self._completed_predicates = set()
        self._builtin_bindings = {}
        self._list_captures = {}
        self._deferred_name_cache = {}
        self._deferred_node_cache = {}
        self._generator_replacement = (frozenset(), frozenset())
        self._ownership_bindings = bindings
        self._ownership_syntax = {'bindings': bindings, 'calls': {}}
        self._nonretaining_parameters = {}
        self._consuming_iterables = set()
        self._iterated_lists = set()
        self._sealed_closures = {}
        self._closure_groups = {}
        self._closure_list_writes = {}
        self._closure_cell_writes = {}
        self._return_slot = None
        self._comprehension_locals = set()
        self._consumer_calls = frozenset()
        self._facade_calls = frozenset()
        self._facade_results = set()
        self._facade_return_complete = None
        self._list_effect_active = False
        self._list_effect_parameters = (None, frozenset())
        self._consumer_stable = {}
        self._string_returns = {}
        self._recursive_closures = set()
        self._closure_worklist = {}
        self._argument_list_reads = set()
        # Closed regions of freshly allocated numeric list trees. Aliases may
        # select nested lists, but every surviving leaf must stay numeric.
        # Escapes retire the whole allocation site, including known aliases;
        # a later loop allocation cannot resurrect an escaped object's proof.
        self.numeric_lists = {}
        self.numeric_regions = set()
        self._retired_numeric_regions = set()
        self._numeric_literal_shapes = {}

    def visit(self, node):
        previous = self._binding_site
        self._binding_site = node
        try:
            if (self._sql_callable_escape_sites is None
                    and (self._ownership_bindings is not None or self._generator_scope)):
                self._sql_callable_escape_sites = self.ownership_bindings().escaped_sql_methods()
            if not isinstance(node, ast.expr):
                result = super().visit(node)
                if (self._sql_callable_escape_sites and node in self._sql_callable_escape_sites
                        and not self.ownership_bindings().covered_sql_method_escape(node)):
                    raise SQLFlowLimit('SQL execution callable escapes its modeled binding; analysis is incomplete')
                return result
            self.step()
            # The same AST may run on another branch, loop iteration or finally
            # exit. Recompute its snapshot instead of reusing a previous store.
            self._evaluated_values.pop(node, None)
            if isinstance(node, ast.Call):
                self._evaluated_call_targets.pop(node, None)
            if isinstance(node, ast.Compare):
                self._evaluated_comparison_truths.pop(node, None)
            result = super().visit(node)
            if node not in self._evaluated_values:
                self._evaluated_values[node] = self.value_facts(node)
            if (self._sql_callable_escape_sites and node in self._sql_callable_escape_sites
                    and not self.ownership_bindings().covered_sql_method_escape(node)):
                raise SQLFlowLimit('SQL execution callable escapes its modeled binding; analysis is incomplete')
            return result
        except SQLFlowLimit as exc:
            if not exc.components:
                component = {
                    'symbol': '.'.join(getattr(scope, 'name', '<lambda>')
                                       for scope in self._generator_scope
                                       if isinstance(scope, (ast.ClassDef, ast.FunctionDef,
                                                             ast.AsyncFunctionDef, ast.Lambda))) or '<module>',
                    'reason': str(exc),
                }
                if getattr(node, 'lineno', None) is not None:
                    component['start_line'] = node.lineno
                    component['end_line'] = getattr(node, 'end_lineno', None) or node.lineno
                exc.components = (component,)
            raise
        finally:
            self._binding_site = previous

    @staticmethod
    def join_value_facts(*facts):
        references = frozenset().union(*(SQLInjectionAnalyzer.generator_refs(fact) for fact in facts))
        if references and any(not SQLInjectionAnalyzer.generator_refs(fact) for fact in facts):
            references |= {None}
        combined = (join_sql_risks(*(fact[0] for fact in facts)),
                join_sql_risks(*(fact[1] for fact in facts)),
                join_sql_risks(*(fact[2] for fact in facts)),
                any(fact[3] for fact in facts),
                max((fact[4] for fact in facts), key=RISK_ORDER.__getitem__, default='unknown'),
                references,
                *SQLInjectionAnalyzer.join_kinds(*(SQLInjectionAnalyzer.fact_kinds(fact) for fact in facts)))
        numeric = {SQLInjectionAnalyzer.numeric_fact_reference(fact) for fact in facts}
        if len(numeric) == 1 and None not in numeric:
            return SQLInjectionAnalyzer.with_numeric_reference(combined, next(iter(numeric)))
        return combined

    @staticmethod
    def generator_refs(facts):
        return facts[5] if len(facts) > 5 else frozenset()

    @staticmethod
    def fact_kinds(facts):
        return facts[6:8] if len(facts) >= 8 else ('', '')

    @staticmethod
    def with_kinds(facts, kind, element_kind=''):
        return (*facts[:5], SQLInjectionAnalyzer.generator_refs(facts), kind, element_kind)

    @staticmethod
    def set_update_capabilities(kind):
        """May-call capabilities authorize refusal, never native execution.

        Exact sets retain their ordinary shape. A mixed receiver/callable
        join instead carries a finite frozenset of possible capabilities;
        it must not acquire an exact builtin type or an exhaustion proof.
        Keeping these in the value lattice preserves saved aliases across
        loop/finally re-evaluation and kills them on definite overwrites.
        """
        if kind == 'set':
            return frozenset({'receiver'})
        return kind if isinstance(kind, frozenset) else frozenset()

    @staticmethod
    def hash_safe_shape(shape):
        """Exact immutable builtin keys cannot invoke user hash/equality code.

        A mixed primitive/tuple join retains only this capability, never a
        numeric or string operation contract. The same bound as tuple shape
        inference prevents recursive wrapping from growing the proof forever.
        """
        for _ in range(64):
            if shape in {'str', 'number', 'none', 'scalar', 'hashable'} or shape == ():
                return True
            if not (isinstance(shape, tuple) and len(shape) == 2 and shape[0] == 'tuple'):
                return False
            shape = shape[1]
        return False

    @staticmethod
    def join_element_shapes(*shapes):
        # () means no possible element, unlike '' (an unknown element).
        # Appending to [] and joining a zero-trip loop must not destroy a
        # proved element type. Immutable tuple elements retain their nested
        # shape; mutable child containers never receive this proof.
        present = {shape for shape in shapes if shape != ()}
        if not present:
            return ()
        if len(present) == 1:
            return next(iter(present))
        capabilities = frozenset().union(*(
            SQLInjectionAnalyzer.set_update_capabilities(shape) for shape in present))
        if capabilities:
            return capabilities
        if all(isinstance(shape, tuple) and len(shape) == 2 and shape[0] == 'tuple'
               for shape in present):
            return ('tuple', SQLInjectionAnalyzer.join_element_shapes(*(shape[1] for shape in present)))
        if present <= {'str', 'number', 'none', 'scalar'}:
            return 'scalar'
        if all(SQLInjectionAnalyzer.hash_safe_shape(shape) for shape in present):
            return 'hashable'
        return ''

    @staticmethod
    def join_kinds(*pairs):
        kinds = {pair[0] for pair in pairs}
        if len(kinds) != 1:
            capabilities = frozenset().union(*(
                SQLInjectionAnalyzer.set_update_capabilities(kind) for kind in kinds))
            if capabilities:
                return capabilities, ''
            if kinds and kinds <= {'number', 'str', 'none', 'scalar'}:
                # A lexical cell can alternate between exact immutable
                # primitives. Keep that non-aliasing fact without claiming
                # the particular numeric/string operations of either arm.
                return 'scalar', ''
            if kinds and all(SQLInjectionAnalyzer.hash_safe_shape(
                    SQLInjectionAnalyzer.element_shape(pair)) for pair in pairs):
                return 'hashable', ''
            return '', ''
        return next(iter(kinds)), SQLInjectionAnalyzer.join_element_shapes(*(pair[1] for pair in pairs))

    @staticmethod
    def element_shape(pair):
        kind, element = pair
        if kind == 'tuple' and (element == () or element in {'str', 'number', 'none', 'scalar', 'hashable'}
                                or isinstance(element, tuple)):
            shape = kind, element
            current = shape
            for _ in range(64):
                if not (isinstance(current, tuple) and len(current) == 2):
                    return shape
                current = current[1]
            # A loop can keep wrapping the prior tuple in a new tuple. A
            # finite abstract shape must widen, rather than growing until
            # Python's recursion limit or the unrelated SQL step budget.
            return kind
        return kind

    @staticmethod
    def element_facts(facts):
        shape = SQLInjectionAnalyzer.fact_kinds(facts)[1]
        pair = shape if isinstance(shape, tuple) and len(shape) == 2 else (
            shape if isinstance(shape, (str, frozenset)) else '', 'str' if shape == 'str' else '')
        return SQLInjectionAnalyzer.with_kinds(facts, *pair)

    @staticmethod
    def numeric_fact_reference(facts):
        return facts[9] if len(facts) > 9 else None

    @staticmethod
    def with_numeric_reference(facts, reference):
        return (*facts[:8], facts[8] if len(facts) > 8 else (), reference)

    def numeric_reference(self, value):
        if not self.numeric_regions:
            return None
        reference = self.numeric_fact_reference(self.value_facts(value))
        if (reference is not None and reference[0] in self.numeric_regions
                and reference[0] not in self._retired_numeric_regions):
            return reference
        return None

    @staticmethod
    def record_fields(reference):
        identity = reference[0]
        return identity[2] if len(identity) > 2 else None

    def record_element_kind(self, reference, index):
        fields = self.record_fields(reference)
        if isinstance(index, ast.Constant) and type(index.value) is int:
            position = index.value
        elif (isinstance(index, ast.UnaryOp) and isinstance(index.op, ast.USub)
                and isinstance(index.operand, ast.Constant) and type(index.operand.value) is int):
            position = -index.operand.value
        else:
            raise SQLFlowLimit('SQL record field index is unresolved; analysis is incomplete')
        if not -len(fields) <= position < len(fields):
            raise SQLFlowLimit('SQL record field bounds are unresolved; analysis is incomplete')
        return fields[position]

    def literal_record_fields(self, value):
        if not isinstance(value, ast.List) or not 1 < len(value.elts) <= 64:
            return None
        fields = []
        for item in value.elts:
            self.step()
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                fields.append('str')
            elif self.numeric_literal_depth(item) == 0:
                fields.append('number')
            else:
                return None
        return tuple(fields) if set(fields) == {'str', 'number'} else None

    def record_value_matches(self, value, fields):
        if not isinstance(value, ast.List) or len(value.elts) != len(fields):
            return False
        for item, expected in zip(value.elts, fields):
            self.step()
            facts = self.value_facts(item)
            if (self.fact_kinds(facts)[0] != expected or any(facts[:3])
                    or expected == 'str' and facts[4] != 'static'):
                return False
        return True

    def borrowed_child_read(self, value):
        scope, names = self._list_effect_parameters
        return (self._list_effect_active and self._generator_scope and self._generator_scope[-1] is scope
                and isinstance(value, ast.Name) and value.id in names)

    def retire_numeric_region(self, identity):
        self.numeric_regions.discard(identity)
        self._retired_numeric_regions.add(identity)
        for name, reference in self.numeric_lists.items():
            if reference[0] == identity:
                self.exclusive_lists.discard(name)
                self.value_kinds[name] = ('list', '')

    def numeric_literal_depth(self, value):
        """Depth of an exact, homogeneous numeric list literal, or None."""
        if value in self._numeric_literal_shapes:
            return self._numeric_literal_shapes[value]
        self.step()
        depth = None
        if isinstance(value, ast.Constant) and type(value.value) in {bool, int, float, complex}:
            depth = 0
        elif isinstance(value, ast.UnaryOp) and isinstance(value.op, (ast.UAdd, ast.USub)):
            if self.numeric_literal_depth(value.operand) == 0:
                depth = 0
        elif isinstance(value, ast.List):
            children = {self.numeric_literal_depth(item) for item in value.elts}
            if not children:
                depth = 1
            elif None not in children and len(children) == 1:
                depth = next(iter(children)) + 1
                if depth > 64:
                    raise SQLFlowLimit('SQL numeric list nesting exceeded; analysis is incomplete')
        self._numeric_literal_shapes[value] = depth
        return depth

    def grant_numeric_region(self, target, value):
        if not isinstance(target, ast.Name) or not isinstance(value, ast.List):
            return
        depth = self.numeric_literal_depth(value)
        fields = None
        if depth is None and value.elts:
            shapes = {self.literal_record_fields(item) for item in value.elts}
            if len(shapes) == 1 and None not in shapes:
                fields = next(iter(shapes))
                depth = 2
        # Ordinary scalar lists already have the existing private-list proof.
        # Regions are needed only when indexing creates a nested-list alias.
        if depth is None or depth < 2 or not self._generator_scope:
            return
        scope = self._generator_scope[-1]
        if (not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
                or target.id not in self.exclusive_lists
                or self.ownership_bindings().dynamic_namespace
                or self.ownership_bindings().builtin_namespace):
            return
        identity = (scope, value, fields) if fields is not None else (scope, value)
        if identity not in self._retired_numeric_regions:
            self.numeric_regions.add(identity)
            self.numeric_lists[target.id] = (identity, depth)

    def numeric_mutation(self, receiver, value, *, extending=False):
        """Keep a closed region only for a type-preserving intrinsic write."""
        reference = self.numeric_reference(receiver)
        if reference is None:
            return None
        _, depth = reference
        fields = self.record_fields(reference)
        if fields is not None:
            values = value.elts if extending and isinstance(value, ast.List) else [value]
            if depth != 2 or not all(self.record_value_matches(item, fields) for item in values):
                raise SQLFlowLimit('SQL primitive record mutation is unresolved; analysis is incomplete')
            return reference
        expected = depth if extending else depth - 1
        valid = (self.numeric_literal_depth(value) == expected if expected else
                 self.value_kind(value)[0] == 'number')
        if extending and depth == 1 and self.value_kind(value)[0] == 'range':
            valid = True
        if not valid or any(self.value_facts(value)[:3]):
            raise SQLFlowLimit('SQL nested numeric list mutation is unresolved; analysis is incomplete')
        return reference

    def widen_numeric_region(self, reference, facts):
        for name, linked in list(self.numeric_lists.items()):
            if linked[0] != reference[0]:
                continue
            before = self.value_facts(ast.Name(id=name, ctx=ast.Load()))
            sites = self.binding_sites.get(name, frozenset({None}))
            owned = name in self.exclusive_lists
            combined = self.with_kinds(self.join_value_facts(before, facts), 'list',
                                       ('' if self.record_fields(linked) else 'number') if linked[1] == 1 else 'list')
            self.bind_value_facts([name], self.with_numeric_reference(combined, linked))
            self.binding_sites[name] = sites
            if owned:
                self.exclusive_lists.add(name)

    def retire_numeric_arguments(self, expressions):
        if not self.numeric_regions:
            return
        pending = list(expressions)
        while pending:
            self.step()
            expression = pending.pop()
            reference = self.numeric_reference(expression) if isinstance(expression, ast.expr) else None
            if reference is not None:
                self.retire_numeric_region(reference[0])
                raise SQLFlowLimit('SQL numeric list call escape is unresolved; analysis is incomplete')
            elif not isinstance(expression, (ast.Call, ast.Subscript)):
                pending.extend(ast.iter_child_nodes(expression))

    def numeric_alias_assignment(self, targets, value):
        reference = self.numeric_reference(value)
        if reference is None or self._generator_scope[-1] is not reference[0][0]:
            return False
        bindings = self.ownership_bindings()
        if not all(isinstance(target, ast.Name) and target.id not in bindings.indirect_rebindings
                   and target.id not in self.deferred_list_captures for target in targets):
            return False
        if isinstance(value, ast.Name):
            # The outer name is now aliased. The closed-region invariant,
            # rather than exclusive single-name ownership, guards its writes.
            self.exclusive_lists.discard(value.id)
        return True

    @property
    def issues(self):
        return self.visible_sink_findings('critical', 'py.security.sql-injection')

    @property
    def warn_issues(self):
        return self.visible_sink_findings('warning', 'py.security.sql-injection-unproven')

    def visible_sink_findings(self, severity, rule):
        if not self._sink_risks:
            return []
        if self._suppression_index is None:
            self._suppression_index = build_index(self.text, lang='python')
        return [(line, code) for risk, line, code in self._sink_risks.values()
                if risk == severity and not self._suppression_index.is_suppressed(line, rule)]

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
        kinds = {name: SQLInjectionAnalyzer.join_kinds(*(state[9].get(name, ('', '')) for state in present))
                 for name in set().union(*(state[9] for state in present))}
        kinds = {name: pair for name, pair in kinds.items() if pair != ('', '')}
        exclusive = set.intersection(*(state[10] for state in present))
        deferred = set().union(*(state[11] for state in present))
        sites = {name: frozenset().union(*(state[12].get(name, frozenset({None})) for state in present))
                 for name in set().union(*(state[12] for state in present))}
        numeric_lists = {}
        for name in set().union(*(state[13] for state in present)):
            references = {state[13].get(name) for state in present if name in state[5] or name in state[13]}
            if len(references) != 1 or None in references:
                raise SQLFlowLimit('SQL numeric list alias join is unresolved; analysis is incomplete')
            numeric_lists[name] = next(iter(references))
        numeric_regions = set().union(*(state[14] for state in present))
        return (unsafe, weak, fragments, selects, templates, values, generators, phases,
                validated, kinds, exclusive, deferred, sites, numeric_lists, numeric_regions)

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
                try:
                    result = self.visit(node)
                except SQLNoNormalReturn:
                    result = {}
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
                    # Exception and pattern captures store their binding as
                    # a string, not a Name(Store) child. They can shadow a
                    # builtin consumer just as an ordinary assignment does.
                    if type(child).__name__ in {'ExceptHandler', 'MatchAs', 'MatchStar'} and child.name:
                        names.add(child.name)
                    if type(child).__name__ == 'MatchMapping' and child.rest:
                        names.add(child.rest)
                    if isinstance(child, (ast.Import, ast.ImportFrom)):
                        names.update(alias.asname or alias.name.split('.')[0] for alias in child.names)
                    pending.extend(ast.iter_child_nodes(child))
                self._builtin_bindings[scope] = frozenset(names)
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
        # An AST-keyed site records execution of this particular definition
        # without confusing a sibling's same-named local or a prior binding.
        self.bind_value_facts([node.name], (None, None, None, False, 'unknown'))
        self.binding_sites[node.name] = frozenset({node})
        self.binding_sites[node] = frozenset({node})
        bindings = self.ownership_bindings()
        parent = bindings.owner_scopes[node]['parent']
        if (self._literal_statement_scopes is not None and node not in self._literal_statement_scopes
                and parent is not None and (isinstance(parent['node'], ast.Module)
                    or isinstance(parent['node'], ast.ClassDef) and parent['parent'] is not None
                    and isinstance(parent['parent']['node'], ast.Module))):
            # Literal SQL elsewhere cannot depend on this deferred body.
            # Keep the SQL-bearing scope itself on the complete flow path,
            # including its callback, generator and ownership refusals.
            return
        if (node in bindings.independent_functions
                and node not in bindings.sql_method_escape_owners
                and not bindings.dynamic_namespace and not bindings.builtin_namespace):
            return
        sealed = self.sealed_list_captures(node)
        if not sealed:
            sealed = self.seal_recursive_siblings(node)
        if (not sealed and node in self._closure_list_writes
                and self.declared_closure_cells(node)):
            # A callable alias or an unsupported lexical owner must not turn
            # later nonlocal writes into a discarded definition-time store.
            raise SQLFlowLimit('SQL closure cell ownership is unresolved; analysis is incomplete')
        self.defer_lists([node])
        self.exclusive_lists.update(sealed)
        self.deferred_list_captures.difference_update(sealed)
        if sealed:
            # This local callable cannot escape or be replaced, and every
            # invocation is interpreted by sealed_closure_call. Its body is
            # deferred until those calls, with actual lexical/input facts;
            # executing it here invents effects for an uncalled definition.
            return
        outer, enclosing_raise = self.sql_state(), self._pending_raise
        enclosing_returns, self._return_slot = self._return_slot, None
        self._pending_raise = None
        self.validated.clear()
        self.exclusive_lists.clear()
        self.exclusive_lists.update(sealed)
        self.numeric_lists.clear()
        self.numeric_regions.clear()
        self.deferred_list_captures.clear()
        parameters = _all_parameters(node)
        self.unsafe_sql_vars.difference_update(parameters)
        self.weak_sql_vars.difference_update(parameters)
        self.sql_template_vars.difference_update(parameters)
        for parameter in parameters:
            self.fragment_sql_vars.pop(parameter, None)
            self.select_sql_vars.pop(parameter, None)
            self.generator_bindings.pop(parameter, None)
            self.value_kinds.pop(parameter, None)
            self.binding_sites.pop(parameter, None)
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
            self._pending_raise = enclosing_raise
            self._return_slot = enclosing_returns

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        # Defaults execute now; the deferred body has its own bindings and
        # must not mutate the defining scope or raise into its try block.
        self.visit(node.args)
        self.defer_lists([node.body])
        outer, enclosing_raise = self.sql_state(), self._pending_raise
        self.validated.clear()
        self.numeric_lists.clear()
        self.numeric_regions.clear()
        self.bind_value_facts(_all_parameters(node), (None, None, None, False, 'tainted'))
        self._pending_raise = None
        scope = self._generator_scope
        self._generator_scope = (*scope, node)
        try:
            try:
                self.visit(node.body)
            except SQLNoNormalReturn:
                # A nonreturning deferred body cannot prevent creation of
                # the lambda object in the enclosing execution.
                pass
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
        self.defer_lists([node])
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
                self.generator_bindings.copy(), self.generator_phases.copy(), self.validated.copy(),
                self.value_kinds.copy(), self.exclusive_lists.copy(), self.deferred_list_captures.copy(),
                self.binding_sites.copy(), self.numeric_lists.copy(), self.numeric_regions.copy())

    def restore_sql_state(self, state):
        (self.unsafe_sql_vars, self.weak_sql_vars, self.fragment_sql_vars,
         self.select_sql_vars, self.sql_template_vars, self.value_risks,
         self.generator_bindings, self.generator_phases, self.validated,
         self.value_kinds, self.exclusive_lists, self.deferred_list_captures,
         self.binding_sites, self.numeric_lists, self.numeric_regions) = (part.copy() for part in state)

    def visit_If(self, node):
        self.visit(node.test)
        incoming = self.sql_state()
        truth = self.condition_truth(node.test)
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

    @staticmethod
    def literal_comparison_truth(left, operator, right):
        """Compare only parsed builtin constants, without invoking source code."""
        if not isinstance(left, ast.Constant) or not isinstance(right, ast.Constant):
            return None
        a, b = left.value, right.value
        if type(a) not in {type(None), bool, int, float, complex, str} or type(b) not in {
                type(None), bool, int, float, complex, str}:
            return None
        if isinstance(operator, (ast.Is, ast.IsNot)):
            # Only None/bool are language-guaranteed singletons. Equal string
            # or numeric literals do not prove identity across implementations.
            if not (a is None or b is None or isinstance(a, bool) or isinstance(b, bool)):
                return None
            return (a is b) if isinstance(operator, ast.Is) else (a is not b)
        try:
            if isinstance(operator, ast.Lt):
                return a < b
            if isinstance(operator, ast.LtE):
                return a <= b
            if isinstance(operator, ast.Gt):
                return a > b
            if isinstance(operator, ast.GtE):
                return a >= b
            if isinstance(operator, ast.Eq):
                return a == b
            if isinstance(operator, ast.NotEq):
                return a != b
            if isinstance(operator, ast.In):
                return a in b
            if isinstance(operator, ast.NotIn):
                return a not in b
        except TypeError:
            # Incompatible builtin types retain the existing possible-raise
            # edge; they are not evidence for either normal truth value.
            return None
        return None

    def condition_truth(self, node):
        """Truth testing inside an effectful predicate must be intrinsic.

        Unknown objects can mutate SQL state in __bool__ or __len__, not
        merely raise. Keep those generators incomplete until their callback
        effects can be modeled. Exact builtin shapes need no such callback;
        an unknown Boolean value still has both short-circuit successors.
        """
        if not self._short_circuiting:
            return self.literal_truth(node)
        self.step()
        kind = self.value_kind(node)[0]
        if kind not in {
                'number', 'str', 'none', 'scalar', 'hashable', 'tuple', 'list',
                'dict', 'set', 'frozenset', 'range'}:
            raise SQLFlowLimit('SQL generator truth callbacks are unresolved; analysis is incomplete')
        if kind == 'none':
            return False
        if isinstance(node, ast.NamedExpr):
            return self.condition_truth(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            if not any(isinstance(item, ast.Starred) for item in node.elts):
                return bool(node.elts)
        if isinstance(node, ast.Dict) and all(key is not None for key in node.keys):
            return bool(node.keys)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            truth = self.condition_truth(node.operand)
            return None if truth is None else not truth
        if isinstance(node, ast.Compare):
            return self._evaluated_comparison_truths.get(node)
        return self.literal_truth(node)

    def visit_For(self, node):
        consuming, iterated = self._consuming_iterables, self._iterated_lists
        self._consuming_iterables = consuming | {node.iter} if isinstance(node, ast.For) else consuming
        iterable = node.iter
        if (isinstance(iterable, ast.Call) and isinstance(iterable.func, ast.Name)
                and iterable.func.id in {'iter', 'reversed'} and self.builtin_is_unshadowed(iterable.func.id)
                and len(iterable.args) == 1 and not iterable.keywords):
            iterable = iterable.args[0]
        roots = ({(self._generator_scope[-1], iterable.id)}
                 if self._generator_scope and isinstance(iterable, ast.Name)
                 and iterable.id in self.exclusive_lists else set())
        self._iterated_lists = iterated | roots
        try:
            return self.visit_for_flow(node)
        finally:
            self._consuming_iterables, self._iterated_lists = consuming, iterated

    def visit_for_flow(self, node):
        if isinstance(node, ast.For) and isinstance(node.iter, (ast.List, ast.Tuple)):
            if not any(isinstance(value, ast.Starred) for value in node.iter.elts):
                items = []
                for value in node.iter.elts:
                    self.visit(value)
                    items.append(self.assignment_bindings(node.target, value))
                self.escape_lists(node.iter.elts)
                return self.finite_loop(node, items)
        self.visit(node.iter)
        facts = self.value_facts(node.iter)
        references = self.generator_refs(facts)
        if references:
            known = references - {None}
            if (not isinstance(node, ast.For) or not known
                    or any(self.generator_has_writes_or_sinks(identity) for identity in known)):
                raise SQLFlowLimit('SQL generator streaming consumption is unsupported; analysis is incomplete')
            # A branch can supply an ordinary iterable instead. Its may-flow
            # facts remain an alternative, without aliasing its yielded items
            # to the generator object from another branch.
            ordinary = self.element_facts(self.with_kinds(facts[:5], *self.fact_kinds(facts))) if None in references else None
            return self.loop(node, ordinary, generators=known)
        return self.loop(node, self.iteration_facts(node.iter))

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
            for target, facts in bindings:
                self.store_assignment(target, facts)
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

    def loop(self, node, iterable_facts=None, *, generators=frozenset()):
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
            if generators:
                # Re-evaluate late-bound projections on every loop backedge.
                # The consumer body may change a free variable between yields.
                # Projecting all possible yields overapproximates the next
                # value. Reprobe after body writes rather than freezing the
                # first yield or granting a deferred validator's proof.
                projected = [] if iterable_facts is None else [iterable_facts]
                for generator in generators:
                    if self.generator_phases.get(generator) == frozenset({'done'}):
                        continue
                    facts, probe = self.generator_projection(generator)
                    if self.generator_refs(facts):
                        raise SQLFlowLimit('SQL generator-valued streaming projection is unsupported; analysis is incomplete')
                    projected.append(facts)
                    self.validated.intersection_update(probe.validated)
                    self._attribute_epoch = max(self._attribute_epoch, probe._attribute_epoch)
                    self.generator_phases[generator] = frozenset({'partial'})
                yielded = self.join_value_facts(*projected)
                can_iterate = bool(projected)
            else:
                yielded = iterable_facts
                can_iterate = True
            truth = None
            if while_loop:
                self.visit(node.test)
                truth = self.condition_truth(node.test)
                if truth is None:
                    self.note_possible_raise()
            else:
                # Iterator advancement can fail before the target is bound.
                self.note_possible_raise()
            tested = self.sql_state()
            exhausted = tested if truth is not True else None
            if generators and exhausted is not None:
                # The normal exhaustion edge has finished every possible
                # generator. Break/raise/return edges retain partial cursors.
                exhausted = (*exhausted[:7], {
                    **exhausted[7], **{identity: frozenset({'done'}) for identity in generators}
                }, *exhausted[8:])
            if not while_loop:
                for target, facts in self.unpacking_bindings(node.target, yielded):
                    self.store_assignment(target, facts)
            body = self.statements(node.body, self.sql_state()) if truth is not False and can_iterate else {}
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
        if self._return_slot is not None:
            if (self._facade_return_complete is not None and node.value is not None
                    and self.value_facts(node.value)[4] != 'static'
                    and self.unresolved_facade_return(node.value)):
                # Visiting a wrapper is not a completed projection of an
                # unsupported inner result. Keep that returned dependency
                # visible to its eventual consumer, including through a
                # branch, local assignment or returned container.
                self._facade_return_complete = False
            self.bind_value_facts([self._return_slot], self.value_facts(node.value) if node.value is not None
                                  else (None, None, None, False, 'static'))
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
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
                and node.attr == 'update'):
            capabilities = self.set_update_capabilities(self.value_kind(node.value)[0])
            methods = ({'bound'} if 'receiver' in capabilities else set())
            if 'constructor' in capabilities:
                methods.add('unbound')
            if methods:
                # Capture the receiver now. Later argument or alias writes
                # cannot redirect an already loaded bound method.
                self._evaluated_values[node] = self.with_kinds(
                    self.value_facts(node), frozenset(methods))
        if self._short_circuiting and isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            bindings = self.ownership_bindings()
            protocols = self.generator_protocol_names()
            if (f'property:{node.attr}' in protocols
                    or protocols.intersection({'__getattribute__', '__getattr__'})):
                raise SQLFlowLimit('SQL generator attribute callbacks are unresolved; analysis is incomplete')
            # Attribute chains naming a modeled database operation keep its
            # API contract. Other opaque properties can mutate captured heap
            # state even when no lexical nonlocal/global store is visible.
            root = node
            parent = bindings.parents.get(root)
            while isinstance(parent, ast.Attribute) and parent.value is root:
                root, parent = parent, bindings.parents.get(parent)
            database_access = (isinstance(parent, ast.Call) and parent.func is root
                               and (sql_sink_name(parent, bindings) or self.generator_database_fetch(parent)))
            primitive_method = (self.value_kind(node.value)[0] == 'str'
                                and callable(getattr(str, node.attr, None)))
            if not database_access and not primitive_method:
                raise SQLFlowLimit('SQL generator attribute effects are unresolved; analysis is incomplete')
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
                and node.attr in LIST_MUTATORS
                and (self.value_kind(node.value)[0] == 'list'
                     or isinstance(node.value, ast.Name) and node.value.id == 'list'
                     and self.builtin_is_unshadowed('list'))
                and node not in self.ownership_bindings().direct_callees):
            # A bound method retains the mutable list even when assigning it
            # revokes the list's exclusive name. Do not later interpret an
            # aliased call as having no effect on the original receiver.
            raise SQLFlowLimit('SQL list mutation capability escapes; analysis is incomplete')
        if isinstance(getattr(node, 'ctx', None), (ast.Store, ast.Del)):
            # Without heap alias proof, a write through any alias can replace
            # a checked property. Never retain a stale attribute validation.
            self.invalidate_attribute_validations()
        self.note_possible_raise()

    def visit_Subscript(self, node):
        self.visit(node.value)
        receiver = self.value_facts(node.value)
        # The receiver is loaded before its index (and before an augmented
        # assignment's RHS). Later rebinding must not redirect the old store.
        name = node.value.id if isinstance(node.value, ast.Name) else None
        self._indexed_receivers[node] = (self.binding_sites.get(name, frozenset({None})),
                                         name in self.exclusive_lists)
        self.visit(node.slice)
        indices = ([index for index in (node.slice.lower, node.slice.upper, node.slice.step)
                    if index is not None] if isinstance(node.slice, ast.Slice) else [node.slice])
        if (self._short_circuiting and self.fact_kinds(receiver)[0] in {'list', 'tuple', 'str', 'range'}
                and any(self.value_kind(index)[0] not in
                        ({'number', 'none'} if isinstance(node.slice, ast.Slice) else {'number'})
                        for index in indices)):
            # Exact sequence receivers still invoke an opaque index's
            # __index__. Its mutation can change SQL in a later iteration.
            raise SQLFlowLimit('SQL generator index callbacks are unresolved; analysis is incomplete')
        if (self._short_circuiting and self.fact_kinds(receiver)[0] == 'dict'
                and not self.hash_safe_shape(self.element_shape(self.value_kind(node.slice)))):
            raise SQLFlowLimit('SQL generator lookup callbacks are unresolved; analysis is incomplete')
        if (self._short_circuiting and self.fact_kinds(receiver)[0]
                not in {'list', 'tuple', 'str', 'range'}
                and (self.has_collection_key_callbacks()
                     or self.fact_kinds(receiver)[0] != 'dict'
                     and self.generator_protocol_names().intersection({'__getitem__', '__index__'}))):
            # Lookup may also compare a resident dictionary key. Proving the
            # lookup key alone cannot rule out that stored key's __eq__.
            raise SQLFlowLimit('SQL generator indexing callbacks are unresolved; analysis is incomplete')
        if (isinstance(node.ctx, ast.Load) and self.borrowed_child_read(node.value)
                and self.fact_kinds(receiver)[1] not in {'str', 'number'}):
            raise SQLFlowLimit('SQL list helper child aliases are unresolved; analysis is incomplete')
        reference = self.numeric_fact_reference(receiver)
        if (reference is not None and self.record_fields(reference) and reference[1] == 1
                and isinstance(node.ctx, ast.Del)):
            self.retire_numeric_region(reference[0])
            raise SQLFlowLimit('SQL record length mutation is unsupported; analysis is incomplete')
        if reference is not None and (isinstance(node.slice, ast.Slice)
                                       or any(self.value_kind(index)[0] != 'number' for index in indices)):
            # A slice exports nested aliases into a new outer container; an
            # unknown index can execute callbacks. Neither has a closed proof.
            self.retire_numeric_region(reference[0])
            raise SQLFlowLimit('SQL numeric list index or slice alias is unresolved; analysis is incomplete')
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.invalidate_attribute_validations()
        elif isinstance(node.ctx, ast.Load):
            kind, element = self.fact_kinds(receiver)
            sites, owned = self._indexed_receivers[node]
            if kind == 'list':
                anonymous = not isinstance(node.value, ast.Name) and self.fresh_list(node.value)
                # Index evaluation can mutate or rebind the receiver. Only a
                # still-private binding may lend its current element shape;
                # an escaped alias could have replaced those elements.
                if not anonymous and (not owned or name not in self.exclusive_lists
                        or sites != self.binding_sites.get(name)):
                    kind = ''
                elif not anonymous:
                    current = self.value_facts(ast.Name(id=name, ctx=ast.Load()))
                    receiver = self.join_value_facts(receiver, current)
                    kind, element = self.fact_kinds(receiver)
            if (kind in {'list', 'tuple', 'str', 'range'}
                    and all(self.value_kind(index)[0] == 'number' for index in indices)
                    and not self.ownership_bindings().dynamic_namespace
                    and not self.ownership_bindings().builtin_namespace):
                # Exact builtin indexing preserves existing SQL provenance.
                # This proves only the result's shape, never index purity or
                # a custom __getitem__/__index__ implementation's behavior.
                facts = self.join_value_facts(self.value_facts(node), receiver)
                # Lookup keys are not returned characters/items. A successful
                # exact read inherits the receiver's provenance, rather than
                # fabricating external data from the Subscript syntax itself.
                facts = (*facts[:4], receiver[4], *facts[5:])
                self._evaluated_values[node] = (self.with_kinds(facts, kind, element)
                    if isinstance(node.slice, ast.Slice) else self.element_facts(self.with_kinds(facts, kind, element)))
        if (reference is not None and reference[0] in self.numeric_regions
                and reference[0] not in self._retired_numeric_regions
                and not isinstance(node.slice, ast.Slice)):
            live = [self.value_facts(ast.Name(id=alias, ctx=ast.Load()))
                    for alias, linked in self.numeric_lists.items() if linked[0] == reference[0]]
            receiver = self.join_value_facts(receiver, *live)
            facts = self.join_value_facts(self.value_facts(node), receiver)
            facts = (*facts[:4], receiver[4], *facts[5:])
            depth = reference[1] - 1
            fields = self.record_fields(reference)
            kind = self.record_element_kind(reference, node.slice) if fields and not depth else 'list' if depth else 'number'
            if kind == 'str':
                # Tags remain static builtin strings on every allowed write;
                # a numeric counter's provenance cannot become tag text.
                facts = (None, None, None, facts[3], 'static')
            facts = self.with_kinds(facts, kind, '' if fields and depth == 1 else
                                   'number' if depth == 1 else 'list' if depth else 'str' if kind == 'str' else '')
            self._evaluated_values[node] = (self.with_numeric_reference(facts, (reference[0], depth))
                                            if depth else facts)
        self.note_possible_raise()

    visit_Await = visit_Attribute

    def visit_BinOp(self, node):
        self.visit_Attribute(node)
        if self._short_circuiting and self.value_kind(node)[0] not in {'number', 'str', 'list', 'tuple'}:
            raise SQLFlowLimit('SQL generator operator callbacks are unresolved; analysis is incomplete')

    def visit_UnaryOp(self, node):
        self.visit_Attribute(node)
        if self._short_circuiting and isinstance(node.op, ast.Not):
            self.condition_truth(node.operand)
            self._evaluated_values[node] = self.with_kinds(
                (None, None, None, False, 'static'), 'number')
        elif self._short_circuiting and self.value_kind(node.operand)[0] != 'number':
            raise SQLFlowLimit('SQL generator operator callbacks are unresolved; analysis is incomplete')

    def visit_Compare(self, node):
        if not self._short_circuiting:
            self.visit_Attribute(node)
            if len(node.ops) == 1 and isinstance(node.ops[0], (ast.Is, ast.IsNot)):
                # Identity returns an exact bool, regardless of operand SQL
                # provenance. Visiting both operands above retains effects.
                self._evaluated_values[node] = self.with_kinds(
                    (None, None, None, False, 'static'), 'number')
            return
        # A middle operand is evaluated once and its captured value is reused
        # by the next link. Keep stopped stores separate from the continuing
        # path so a later write cannot erase a short-circuit alternative.
        self.visit(node.left)
        left_node, bypass, result_truth = node.left, None, True
        for index, (operator, right_node) in enumerate(zip(node.ops, node.comparators)):
            self.step()
            try:
                self.visit(right_node)
            except SQLNoNormalReturn:
                if bypass is None:
                    raise
                self.restore_sql_state(bypass)
                # Every surviving normal path stopped at an earlier false
                # link. Preserve that fact for enclosing and/or predicates.
                result_truth = False
                break
            left, right = self.value_kind(left_node), self.value_kind(right_node)
            if isinstance(operator, (ast.Is, ast.IsNot)):
                intrinsic = True
            elif isinstance(operator, (ast.In, ast.NotIn)):
                # Membership can dispatch __contains__/__eq__/__hash__ even
                # though its final result is always an exact bool.
                intrinsic = (right[0] in {'tuple', 'list', 'set', 'frozenset', 'str'}
                             and self.hash_safe_shape(right[1])
                             and self.hash_safe_shape(self.element_shape(left)))
            else:
                intrinsic = (self.hash_safe_shape(self.element_shape(left))
                             and self.hash_safe_shape(self.element_shape(right)))
            if not intrinsic:
                raise SQLFlowLimit('SQL generator comparison callbacks are unresolved; analysis is incomplete')
            self.note_possible_raise()
            truth = self.literal_comparison_truth(left_node, operator, right_node)
            if truth is False or result_truth is True:
                result_truth = truth
            if index < len(node.ops) - 1:
                if truth is not True:
                    bypass = self.join_sql_states(bypass, self.sql_state())
                if truth is False:
                    break
            left_node = right_node
        self.restore_sql_state(self.join_sql_states(bypass, self.sql_state()))
        self._evaluated_comparison_truths[node] = result_truth
        self._evaluated_values[node] = self.with_kinds(
            (None, None, None, False, 'static'), 'number')

    def visit_FormattedValue(self, node):
        self.generic_visit(node)
        if self._short_circuiting:
            protocols = ({'__format__'} if node.conversion == -1 else
                         {'__str__', '__repr__'} if node.conversion == ord('s') else {'__repr__'})
            if (protocols & self.generator_protocol_names()
                    and not self.hash_safe_shape(self.element_shape(self.value_kind(node.value)))):
                raise SQLFlowLimit('SQL generator formatting callbacks are unresolved; analysis is incomplete')
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
            try:
                self.visit(value)
            except SQLNoNormalReturn:
                if bypass is None:
                    raise
                self.restore_sql_state(bypass)
                self.check_numeric_alternatives(values)
                self._evaluated_values[node] = self.join_value_facts(*values)
                return
            if index == len(node.values) - 1:
                values.append(self.value_facts(value))
                break
            truth = self.condition_truth(value)
            if truth is None:
                self.note_possible_raise()
            continuing = True if isinstance(node.op, ast.And) else False
            if truth is not continuing:
                bypass = self.join_sql_states(bypass, self.sql_state())
                values.append(self.value_facts(value))
            if truth is not None and truth is not continuing:
                break
        self.restore_sql_state(self.join_sql_states(bypass, self.sql_state()))
        self.check_numeric_alternatives(values)
        self._evaluated_values[node] = self.join_value_facts(*values)

    def visit_IfExp(self, node):
        self.visit(node.test)
        incoming, branches = self.sql_state(), []
        values = []
        truth = self.condition_truth(node.test)
        if truth is None:
            self.note_possible_raise()
        for expression, selected in ((node.body, True), (node.orelse, False)):
            if truth is not None and truth is not selected:
                continue
            self.restore_sql_state(incoming)
            try:
                self.visit(expression)
            except SQLNoNormalReturn:
                continue
            branches.append(self.sql_state())
            values.append(self.value_facts(expression))
        if not branches:
            raise SQLNoNormalReturn()
        self.restore_sql_state(self.join_sql_states(*branches))
        self.check_numeric_alternatives(values)
        self._evaluated_values[node] = self.join_value_facts(*values)

    def check_numeric_alternatives(self, values):
        references = {self.numeric_fact_reference(facts) for facts in values}
        if any(reference is not None for reference in references) and len(references) > 1:
            raise SQLFlowLimit('SQL numeric list conditional alias is unresolved; analysis is incomplete')

    def has_collection_key_callbacks(self):
        """Visible hashing/equality code cannot be discarded as an exception.

        This extends the existing in-file effect boundary, not a heap proof
        for arbitrary imported objects or opaque returns. The stricter
        dict.fromkeys generator guard remains independent of this check.
        """
        cache = self._ownership_syntax
        if 'collection_key_callbacks' not in cache:
            bindings = self.ownership_bindings()
            protocols = {'__hash__', '__eq__'}
            visible = bool(protocols & bindings.member_writes)
            for function in bindings.key_callbacks:
                self.step()
                visible |= function.name in protocols
            if not visible:
                for call in bindings.calls:
                    self.step()
                    if (call_name(call.func).rsplit('.', 1)[-1]
                            in {'setattr', 'delattr', '__setattr__', '__delattr__'}
                            and any(protocols & (bindings.attribute_name_options(argument) or frozenset())
                                    for argument in call.args[:2])):
                        visible = True
                        break
            cache['collection_key_callbacks'] = visible
        return cache['collection_key_callbacks']

    def check_collection_keys(self, values):
        if not self.has_collection_key_callbacks():
            return
        for facts in values:
            self.step()
            kind, element = self.fact_kinds(facts)
            shape = element if kind == 'frozenset' else self.element_shape((kind, element))
            if not self.hash_safe_shape(shape):
                raise SQLFlowLimit('SQL collection key callbacks are unresolved; analysis is incomplete')

    def collection_key_effects_unmodeled(self):
        """Only inert visible protocol bodies need no callback effect model.

        An SQL sink spelling is not purity: a local execute() may rewrite a
        captured query. Independently reached callback findings stay visible
        when the enclosing hash/equality effects require an incomplete result.
        """
        cache = self._ownership_syntax
        if 'collection_key_effects_unmodeled' not in cache:
            bindings = self.ownership_bindings()
            protocols = {'__hash__', '__eq__'}
            unresolved = bool(protocols & bindings.member_writes or bindings.reflective_member_writes)
            for function in bindings.key_callbacks:
                self.step()
                if function.name not in protocols:
                    continue
                owner = bindings.owner_scopes[function]['parent']
                owner = owner['node'] if owner is not None else None
                if (function.decorator_list or isinstance(owner, ast.ClassDef)
                        and (owner.decorator_list or owner.keywords)):
                    # Decorators and metaclasses may replace a literal body.
                    unresolved = True
                for statement in function.body:
                    self.step()
                    if isinstance(statement, ast.Pass):
                        continue
                    if isinstance(statement, ast.Return) and (
                            statement.value is None or isinstance(statement.value, ast.Constant)):
                        continue
                    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                        continue
                    unresolved = True
            cache['collection_key_effects_unmodeled'] = unresolved
        return cache['collection_key_effects_unmodeled']

    def check_set_update_keys(self, node):
        """Check actual possible emissions without advancing a real cursor."""
        capabilities = self.set_update_capabilities(self.value_kind(node.func)[0])
        if (not capabilities.intersection({'bound', 'unbound'})
                or not self.has_collection_key_callbacks()
                or not self.collection_key_effects_unmodeled()):
            return
        arguments, pending = [], list(reversed(node.args))
        while pending:
            self.step()
            argument = pending.pop()
            if isinstance(argument, ast.Starred):
                if not isinstance(argument.value, (ast.List, ast.Tuple)):
                    # Opaque expansion can hide the receiver and later inputs.
                    self.check_collection_keys([(None, None, None, False, 'unknown')])
                pending.extend(reversed(argument.value.elts))
            else:
                arguments.append(argument)
        offset = 0 if 'bound' in capabilities else 1
        # An unbound method's receiver is not a newly hashed input iterable.
        for argument in [*arguments[offset:], *(keyword.value for keyword in node.keywords)]:
            self.step()
            references = self.generator_refs(self.value_facts(argument))
            if not references:
                self.check_collection_keys(self.collection_key_facts(argument))
                continue
            probe = self.flow_probe()
            try:
                # A mixed generator/non-generator binding remains explicitly
                # unsupported. A partial cursor must never restart at fresh;
                # an exhausted cursor emits no keys and has no hash effects.
                probe.materialize_generators(references, hash_keys=True)
            except SQLNoNormalReturn as exc:
                # May-call recognition cannot remove the real successor.
                raise SQLFlowLimit('SQL set.update key iteration is unresolved; analysis is incomplete') from exc
            finally:
                # A yielded expression can reach SQL before its key protocol
                # becomes unsupported. Preserve that evidence, not the probe's
                # speculative stores or cursor progress.
                for identity, finding in probe._sink_risks.items():
                    previous = self._sink_risks.get(identity)
                    if previous is None or finding[0] == 'critical':
                        self._sink_risks[identity] = finding

    def collection_key_facts(self, value, *, mapping=False):
        """Captured keys of literal inputs; unknown objects keep no proof."""
        self.step()
        if isinstance(value, ast.Dict):
            return [facts for key, item in zip(value.keys, value.values)
                    for facts in (self.collection_key_facts(item, mapping=True) if key is None
                                  else [self.value_facts(key)])]
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            keys = []
            for item in value.elts:
                self.step()
                if isinstance(item, ast.Starred):
                    keys.extend(self.collection_key_facts(item.value, mapping=mapping))
                elif mapping:
                    if isinstance(item, (ast.List, ast.Tuple)) and len(item.elts) == 2:
                        keys.append(self.value_facts(item.elts[0]))
                    else:
                        keys.append((None, None, None, False, 'unknown'))
                else:
                    keys.append(self.value_facts(item))
            return keys
        if mapping:
            return [(None, None, None, False, 'unknown')]
        return [self.iteration_facts(value)]

    def check_collection_constructor(self, node):
        if not self.has_collection_key_callbacks():
            return
        target = self.ownership_bindings().resolve(node.func)
        name = (target[1] if target and target[0] == 'unbound' else
                target[1].removeprefix('builtins.') if target and target[0] == 'import'
                and target[1].startswith('builtins.') else '')
        fromkeys = (name == 'dict.fromkeys' or
                    isinstance(node.func, ast.Attribute) and node.func.attr == 'fromkeys'
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'dict'
                    and self.builtin_is_unshadowed('dict'))
        if name not in {'dict', 'set', 'frozenset'} and not fromkeys:
            return
        if any(isinstance(argument, ast.Starred) for argument in node.args):
            self.check_collection_keys([(None, None, None, False, 'unknown')])
        if node.args and not isinstance(node.args[0], ast.Starred):
            self.check_collection_keys(self.collection_key_facts(
                node.args[0], mapping=name == 'dict'))
        for keyword in node.keywords:
            if keyword.arg is None:
                self.check_collection_keys(self.collection_key_facts(keyword.value, mapping=True))

    def visit_Dict(self, node):
        # ast.iter_child_nodes lists all keys before all values. Python
        # instead evaluates each key immediately before its associated value.
        keys = []
        for key, value in zip(node.keys, node.values):
            if key is not None:
                self.visit(key)
                keys.append(self.value_facts(key))
            else:
                # A ** expansion follows insertion of the preceding block.
                self.check_collection_keys(keys)
                keys = []
            self.visit(value)
            if key is None and self.has_collection_key_callbacks():
                self.check_collection_keys(self.collection_key_facts(value, mapping=True))
        # Plain display expressions all run before BUILD_MAP hashes keys.
        # Keep their known SQL findings before refusing callback effects.
        self.check_collection_keys(keys)
        self.escape_lists([node])

    def visit_List(self, node):
        self.generic_visit(node)
        if isinstance(getattr(node, 'ctx', None), ast.Load):
            self.escape_lists(node.elts)

    visit_Tuple = visit_List

    def visit_Set(self, node):
        self.generic_visit(node)
        if self.has_collection_key_callbacks():
            self.check_collection_keys(self.collection_key_facts(node))
        self.escape_lists(node.elts)

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

    def visit_ListComp(self, node, *, captured=None, consumer_can_raise=False, hash_keys=False,
                       short_circuit=None, reducer=None):
        """Evaluate eager comprehensions in loop/filter order and local scope.

        Literal lists/tuples have exact iteration counts. Dynamic iterables
        reuse the finite SQL-state lattice, including zero-trip and backedge
        paths. Only emitted expressions contribute result values; iterables,
        filters and dictionary keys are not SELECT mapping values.
        """
        if len(node.generators) > 64:
            raise SQLFlowLimit('SQL comprehension nesting exceeded; analysis is incomplete')
        record_reducer = reducer is not None and isinstance(node.elt, ast.List)
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
        stopped = None

        def emit():
            nonlocal produced, stopped
            if isinstance(node, ast.DictComp):
                self.visit(node.key)
                key = self.value_facts(node.key)
                self.visit(node.value)
                self.retire_numeric_arguments([node.key, node.value])
                value = self.value_facts(node.value)
                combined = self.join_value_facts(key, value)
                facts = (combined[0], combined[1], value[1], combined[3], combined[4])
                self.check_collection_keys([key])
                # Hashing a nonliteral key may raise during insertion.
                if not isinstance(node.key, ast.Constant):
                    self.note_possible_raise()
            else:
                self.visit(node.elt)
                self.retire_numeric_arguments([node.elt])
                facts = self.value_facts(node.elt)
                if isinstance(node, ast.SetComp) or hash_keys:
                    self.check_collection_keys([facts])
                if isinstance(node, ast.SetComp) and not isinstance(node.elt, ast.Constant):
                    self.note_possible_raise()
            if reducer is not None:
                self.check_generator_reducer(facts, *reducer, yielded=node.elt)
            if consumer_can_raise:
                if (self._short_circuiting
                        and not record_reducer
                        and not self.hash_safe_shape(self.element_shape(self.fact_kinds(facts)))):
                    raise SQLFlowLimit('SQL generator reducer callbacks are unresolved; analysis is incomplete')
                # A reducer/hash/comparison can fail after this yield while
                # leaving the generator suspended, unlike a body exception
                # which closes it. Preserve that prefix's outer SQL facts.
                phase = self.generator_phases[node]
                self.generator_phases[node] = frozenset({'partial'})
                self.note_possible_raise()
                self.generator_phases[node] = phase
            produced = facts if produced is None else self.join_value_facts(produced, facts)
            if short_circuit is not None:
                truth = self.condition_truth(node.elt)
                continuing = short_circuit == 'all'
                if truth is not continuing:
                    # A successful early return leaves the cursor suspended
                    # at this yield. Keep this prefix out of every backedge:
                    # later iterations cannot overwrite its SQL store.
                    phase = self.generator_phases[node]
                    self.generator_phases[node] = frozenset({'partial'})
                    stopped = self.join_sql_states(stopped, self.sql_state())
                    self.generator_phases[node] = phase
                if truth is not None and truth is not continuing:
                    return None
            return self.sql_state()

        def filtered(index):
            iterated = self._iterated_lists
            iterable = node.generators[index].iter
            if isinstance(iterable, ast.Name) and iterable.id in self.exclusive_lists:
                self._iterated_lists = iterated | {(self._generator_scope[-1], iterable.id)}
            try:
                bypass = None
                for condition in node.generators[index].ifs:
                    self.visit(condition)
                    truth = self.condition_truth(condition)
                    if truth is None:
                        self.note_possible_raise()
                    if truth is not True:
                        bypass = self.join_sql_states(bypass, self.sql_state())
                    if truth is False:
                        return bypass
                result = (level(index + 1, self.sql_state())
                          if index + 1 < len(node.generators) else emit())
                return self.join_sql_states(bypass, result)
            except SQLNoNormalReturn:
                return bypass
            finally:
                self._iterated_lists = iterated

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
            if record_reducer:
                kind, element = self.value_kind(iterable)
                if not (self.hash_safe_shape(self.element_shape((kind, element)))
                        or kind == 'range'
                        or isinstance(iterable, ast.List) and not any(
                            isinstance(item, ast.Starred) for item in iterable.elts)
                        and self.hash_safe_shape(element)):
                    # Fresh records do not make their input iterator or its
                    # released elements callback-free. Retained mutable
                    # iterables need ownership/lifetime identities first.
                    raise SQLFlowLimit('SQL generator reducer iterator callbacks are unresolved; analysis is incomplete')
            if (self._short_circuiting and self.value_kind(iterable)[0]
                    not in {'list', 'tuple', 'str', 'range', 'dict', 'set', 'frozenset'}
                    and self.generator_protocol_names().intersection({'__iter__', '__next__'})):
                raise SQLFlowLimit('SQL generator iterator callbacks are unresolved; analysis is incomplete')
            if (not generator.is_async and isinstance(iterable, (ast.List, ast.Tuple))
                    and not any(isinstance(item, ast.Starred) for item in iterable.elts)):
                # Every iterable element was evaluated before entering its
                # loop, not lazily after earlier body assignments.
                items = [self.assignment_bindings(generator.target, item) for item in iterable.elts]
                current = entered
                for bindings in items:
                    if current is None:
                        break
                    self.step()
                    self.restore_sql_state(current)
                    for target, facts in bindings:
                        self.store_assignment(target, facts)
                    current = filtered(index)
                return current
            facts = self.iteration_facts(iterable)
            header = entered
            while True:
                self.step()
                self.restore_sql_state(header)
                self.note_possible_raise()
                for target, projected in self.unpacking_bindings(generator.target, facts):
                    self.store_assignment(target, projected)
                after = filtered(index)
                updated = self.join_sql_states(entered, after)
                if updated == header:
                    return updated
                header = updated

        enclosing_locals = self._comprehension_locals
        enclosing_short_circuit = self._short_circuiting
        try:
            self._comprehension_locals = enclosing_locals | local_names
            # The admitted mutable-record subset also needs the guarded
            # visitor: filter/operator/property/call callbacks can mutate
            # SQL even when the final yielded record has primitive fields.
            self._short_circuiting = enclosing_short_circuit or short_circuit is not None or record_reducer
            result = level(0, self.sql_state())
            result = self.join_sql_states(result, stopped)
            if result is None:
                raise SQLNoNormalReturn()
            self.restore_sql_state(result)
            facts = produced or (None, None, None, False, 'static')
            if not isinstance(node, ast.GeneratorExp):
                kind = 'dict' if isinstance(node, ast.DictComp) else 'set' if isinstance(node, ast.SetComp) else 'list'
                facts = self.with_kinds(facts, kind, self.element_shape(self.fact_kinds(facts)))
            self._evaluated_values[node] = facts
        finally:
            self._comprehension_locals = enclosing_locals
            self._short_circuiting = enclosing_short_circuit
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
        # A lazy object can outlive this binding and export a referenced list.
        # Without a heap model it must revoke exclusive ownership now.
        self.escape_lists([node])
        self.defer_lists([node.elt, *(condition for generator in node.generators for condition in generator.ifs),
                          *(generator.iter for generator in node.generators[1:])])
        if not isinstance(first, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            self.note_possible_raise()  # constructing the iterator can fail
        aliases = {name for name, refs in self.generator_bindings.items() if node in refs}
        if aliases and not self.replaceable_exhausted_generator(node, aliases):
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

    def replaceable_exhausted_generator(self, node, aliases):
        targets, expressions = self._generator_replacement
        if (node not in expressions or not aliases <= targets or node in self._generator_running
                or self.generator_phases.get(node) != frozenset({'done'})):
            return False
        # The overwritten binding must be the last reference. In particular,
        # another lazy object's captured iterator must not start using this
        # allocation's new contents, nor may the new iterable capture the old
        # object through that same binding.
        captures = [captured for identity, (_, captured, _) in self._generator_specs.items()
                    if identity is not node]
        captures.append({child: self._evaluated_values[child] for child in ast.walk(node.generators[0].iter)
                         if child in self._evaluated_values})
        return not any(node in self.generator_refs(facts) for captured in captures for facts in captured.values())

    def materialize_generators(self, references, *, consumer_can_raise=False, hash_keys=False,
                               short_circuit=None, reducer=None):
        """Consume selected same-scope generators using the comprehension engine.

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
                        self.visit_ListComp(identity, captured=captured, consumer_can_raise=consumer_can_raise,
                                            hash_keys=hash_keys, short_circuit=short_circuit, reducer=reducer)
                        value = self.value_facts(identity)
                        if self.generator_refs(value):
                            raise SQLFlowLimit('SQL generator-valued projection is unsupported; analysis is incomplete')
                        values.append(self.with_kinds(value[:5], *self.fact_kinds(value)))
                    except SQLNoNormalReturn:
                        # A failing alternative must not erase another
                        # selected generator's normal completion. Its error
                        # state is already retained in _pending_raise.
                        continue
                    finally:
                        self._generator_running.remove(identity)
                        # The AST expression still denotes the generator;
                        # its projected values belong to this consumption.
                        self._evaluated_values[identity] = (
                            None, None, None, False, 'unknown', frozenset({identity}))
                else:
                    raise SQLFlowLimit('SQL partial generator consumption is unsupported; analysis is incomplete')
                stores.append(self.sql_state())
        if not stores:
            raise SQLNoNormalReturn()
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
        if self.list_update(node):
            return True
        if not arguments and not receiver:
            return False
        target = self.ownership_call_target(node)
        predicate = (target[1] if target and target[0] == 'unbound' else
                     target[1].removeprefix('builtins.') if target and target[0] == 'import'
                     and target[1] in {'builtins.any', 'builtins.all'} else '')
        if predicate in {'any', 'all'}:
            bindings = self.ownership_bindings()
            if (receiver or len(node.args) != 1 or node.keywords or len(arguments) != 1
                    or arguments[0][0] is not node.args[0] or isinstance(node.args[0], ast.Starred)):
                raise SQLFlowLimit('SQL generator predicate call shape is unresolved; analysis is incomplete')
            finalizers = '__del__' in self.generator_protocol_names()
            retained_predicate = finalizers and self.retained_generator_predicate(node, bindings)
            if finalizers and not retained_predicate:
                # Exhaustion or suspension cleanup can finalize the iterator
                # or its elements, even for an exact builtin container and a
                # read-only predicate. Heap lifetime effects need a model.
                raise SQLFlowLimit('SQL generator finalizer effects are unresolved; analysis is incomplete')
            refs = arguments[0][1]
            protocols = {'__bool__', '__len__', '__contains__', '__eq__', '__ne__',
                         '__lt__', '__le__', '__gt__', '__ge__'}
            requires_model = not retained_predicate and (
                self._short_circuiting or bindings.predicate_callbacks
                or protocols & bindings.member_writes or bindings.reflective_member_writes
                or any(identity is None or self.generator_has_writes_or_sinks(identity)
                       for identity in refs))
            if (predicate in bindings.member_writes or requires_model
                    and (bindings.dynamic_namespace or bindings.builtin_namespace)):
                raise SQLFlowLimit('SQL generator predicate binding is unresolved; analysis is incomplete')
            if bindings.dynamic_namespace or bindings.builtin_namespace:
                # Namespace observation can obscure builtin identity even
                # for a SQL-neutral, read-only argument. Preserve the old
                # opaque-consumer projection below; it still refuses SQL
                # effects and must not grant a proven Boolean return value.
                predicate = ''
        if predicate in {'any', 'all'}:
            if requires_model:
                self.check_generator_callback_writes()
                # Execute SQL sinks and enclosing walrus writes at each
                # reachable yield, preserving exhausted and stopped stores.
                # An effectful partial cursor has no saved instruction
                # pointer and must still refuse a later attempted restart.
                self.materialize_generators(refs, short_circuit=predicate)
                # All admitted truth tests use exact builtin shapes. Their
                # consumer adds no callback/exception after a successful
                # yield; only the modeled generator body can fail and close
                # the cursor. Do not fabricate a partial-cursor error edge.
                self._completed_predicates.add(node)
            else:
                for identity in refs:
                    if self.generator_phases.get(identity) == frozenset({'done'}):
                        continue
                    # Keep the existing read-only projection boundary for
                    # opaque helper effects and captured cursor changes.
                    _, probe = self.read_only_generator_projection(identity)
                    self.validated.intersection_update(probe.validated)
                    self._attribute_epoch = max(self._attribute_epoch, probe._attribute_epoch)
                    self.generator_phases[identity] = frozenset({'partial'})
            self._evaluated_values[node] = self.with_kinds(
                (None, None, None, False, 'static'), 'number')
            return True
        if (isinstance(node.func, ast.Attribute) and node.func.attr == 'fromkeys'
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 'dict'):
            bindings = self.ownership_bindings()
            if (not self.builtin_is_unshadowed('dict') or bindings.dynamic_namespace
                    or bindings.builtin_namespace):
                raise SQLFlowLimit('SQL dict.fromkeys binding is unresolved; analysis is incomplete')
            if (len(node.args) not in {1, 2} or node.keywords
                    or any(isinstance(argument, ast.Starred) for argument in node.args)
                    or len(arguments) != 1 or arguments[0][0] is not node.args[0]):
                raise SQLFlowLimit('SQL dict.fromkeys call shape is unresolved; analysis is incomplete')
            # Python captures the shared default before draining the keys.
            # Mutable/default-generator aliases need a separate heap model.
            default = (self.value_facts(node.args[1]) if len(node.args) == 2 else
                       self.with_kinds((None, None, None, False, 'static'), 'none'))
            if self.fact_kinds(default)[0] not in {'str', 'number', 'none'}:
                raise SQLFlowLimit('SQL dict.fromkeys default alias is unresolved; analysis is incomplete')
            references = arguments[0][1]
            exhausted = all(self.generator_phases.get(identity) == frozenset({'done'})
                            for identity in references)
            keys = self.materialize_generators(references, consumer_can_raise=True)
            # Arbitrary key hashing/equality can mutate enclosing SQL state.
            # Exact primitives and tuples recursively containing only those
            # primitives cannot dispatch those callbacks. SQL provenance is
            # still carried by every element and by the separately saved default.
            if not exhausted and not self.hash_safe_shape(self.element_shape(self.fact_kinds(keys))):
                raise SQLFlowLimit('SQL dict.fromkeys key callbacks are unresolved; analysis is incomplete')
            combined = self.join_value_facts(keys, default)
            self._evaluated_values[node] = self.with_kinds(
                (combined[0], combined[1], default[1], combined[3], combined[4]), 'dict')
            return True
        reducer_name = (target[1] if target and target[0] == 'unbound' else
                        target[1].removeprefix('builtins.') if target and target[0] == 'import'
                        and target[1] in {'builtins.min', 'builtins.max', 'builtins.sorted', 'builtins.sum'} else '')
        opaque_literal_reducer = False
        if (reducer_name in {'min', 'max', 'sorted', 'sum'}
                and not self.closed_generator_builtin_binding(reducer_name)):
            if (self._literal_statement_scopes is None or receiver
                    or any(identity is None or self.generator_has_sql_effects(identity, include_fragments=False)
                           for _, refs in arguments for identity in refs)):
                raise SQLFlowLimit('SQL generator reducer binding is unresolved; analysis is incomplete')
            # Every admitted SQL statement is a literal, and this generator
            # neither supplies SQL nor changes its state. Treat the unresolved
            # consumer as opaque below; do not prove its result or exhaustion.
            # Computed SQL and ambiguous aliases never enter this scoped path.
            reducer_name = ''
            opaque_literal_reducer = True
        if reducer_name in {'min', 'max', 'sorted', 'sum'}:
            bindings = self.ownership_bindings()
            keywords = {keyword.arg: keyword.value for keyword in node.keywords}
            allowed = ({'start'} if reducer_name == 'sum' else
                       {'key', 'reverse'} if reducer_name == 'sorted' else {'key', 'default'})
            if (receiver or len(arguments) != 1 or not node.args or arguments[0][0] is not node.args[0]
                    or any(isinstance(argument, ast.Starred) for argument in node.args)
                    or not keywords.keys() <= allowed or len(keywords) != len(node.keywords)
                    or len(node.args) not in ({1, 2} if reducer_name == 'sum' else {1})
                    or reducer_name == 'sum' and len(node.args) == 2 and 'start' in keywords):
                raise SQLFlowLimit('SQL generator reducer call shape is unresolved; analysis is incomplete')
            start = node.args[1] if len(node.args) == 2 else keywords.get('start')
            # These eagerly captured arguments can invoke protocols before
            # (reverse) or during (start) iteration, even when the generator
            # body itself has no SQL effects. Never infer purity from syntax.
            for argument in (start, keywords.get('reverse')):
                if (argument is not None
                        and not self.hash_safe_shape(self.element_shape(self.value_kind(argument)))):
                    raise SQLFlowLimit('SQL generator reducer argument callbacks are unresolved; analysis is incomplete')
            key = keywords.get('key')
            length_key = (isinstance(key, ast.Name) and key.id == 'len'
                          and self.builtin_is_unshadowed('len')
                          and self.closed_generator_builtin_binding('len'))
            # sorted exhausts its iterable before invoking any key. min/max
            # invoke their keys between yields, so free cells must be read
            # at those different times. Shapes are bounded immutable facts;
            # retaining them cannot retain an analyzed program's objects.
            deferred_keys = set() if reducer_name == 'sorted' else None
            facts = self.materialize_generators(
                arguments[0][1], consumer_can_raise=True, reducer=(key, length_key, deferred_keys))
            if deferred_keys is not None:
                for shape in deferred_keys:
                    self.check_generator_reducer_key(shape, key, length_key)
                if deferred_keys:
                    self.note_possible_raise()
            if start is not None:
                facts = self.join_value_facts(facts, self.value_facts(start))
            if 'default' in keywords:
                facts = self.join_value_facts(facts, self.value_facts(keywords['default']))
            if reducer_name == 'sorted':
                facts = self.with_kinds(facts, 'list', self.element_shape(self.fact_kinds(facts)))
            self._evaluated_values[node] = facts
            return True
        if isinstance(node.func, ast.Name) and self.builtin_is_unshadowed(node.func.id):
            name = node.func.id
            if (name in {'next', 'list', 'tuple', 'set', 'frozenset', 'iter',
                         'str', 'repr', 'bool', 'id', 'type'}
                    and not self.closed_generator_builtin_binding(name)):
                # A lexical builtin name still reads the mutable builtin
                # namespace. A replacement may skip an expected drain,
                # return different SQL, or mutate a captured query while
                # an apparent object observer runs. None of the native
                # result, effect, or exhaustion proofs apply in that case.
                raise SQLFlowLimit('SQL generator builtin binding is unresolved; analysis is incomplete')
            if (name == 'next' and len(node.args) in {1, 2} and not node.keywords
                    and len(arguments) == 1 and arguments[0][0] is node.args[0]):
                refs = arguments[0][1]
                if all(identity is not None and not self.generator_has_writes_or_sinks(identity)
                       for identity in refs):
                    values = [self.value_facts(node.args[1])] if len(node.args) == 2 else []
                    for identity in refs:
                        if self.generator_phases.get(identity) == frozenset({'done'}):
                            continue
                        facts, probe = self.read_only_generator_projection(identity)
                        values.append(facts)
                        self.validated.intersection_update(probe.validated)
                        self._attribute_epoch = max(self._attribute_epoch, probe._attribute_epoch)
                        # Do not claim exhaustion or restart this cursor on a
                        # later full drain. Repeated next() calls conservatively
                        # reproject every possible remaining read-only yield.
                        self.generator_phases[identity] = frozenset({'partial'})
                    if len(node.args) == 1:
                        self.note_possible_raise()  # StopIteration is possible.
                    self._evaluated_values[node] = self.join_value_facts(*values) if values else (
                        None, None, None, False, 'static')
                    return True
            if len(node.args) == 1 and not node.keywords and arguments:
                refs = arguments[0][1]
                if name in {'list', 'tuple', 'set', 'frozenset'}:
                    facts = self.materialize_generators(
                        refs, consumer_can_raise=name not in {'list', 'tuple'},
                        hash_keys=name in {'set', 'frozenset'})
                    facts = self.with_kinds(facts, name, self.fact_kinds(facts)[0])
                    self._evaluated_values[node] = facts
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
        if (self.intrinsic_string_join(node) and len(arguments) == 1
                and arguments[0][0] is node.args[0]):
            # The bound method captures its receiver before the argument and
            # generator body run. Keep that text even when iteration rebinds
            # the separator's name, and consume the selected cursor exactly
            # once through the existing completion/effect model.
            separator = (self.value_facts(node.func.value)
                         if self.string_join_uses_separator(node.args[0], arguments[0][1])
                         else (None, None, None, False, 'static'))
            facts = self.materialize_generators(arguments[0][1])
            combined = self.join_value_facts(facts, separator)
            risk = None if combined[4] == 'static' else 'critical' if combined[4] == 'tainted' else 'warning'
            self._evaluated_values[node] = self.with_kinds((
                join_sql_risks(combined[0], risk if combined[3] else None),
                join_sql_risks(combined[1], risk), join_sql_risks(combined[2], risk),
                combined[3], combined[4]), 'str', 'str')
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
        # GH #222: concatenated iterable data can carry fragment risk without
        # supplying SQL. The complete literal-statement inventory proves that
        # no SQL slot can consume those fragments, including through aliases
        # or other scopes. Keep complete SQL exports, writes, sinks and cursor
        # effects on the ordinary refusal path; no consumer identity or full
        # exhaustion is inferred from this proof.
        if opaque_literal_reducer or all(
                identity is not None and not self.generator_has_sql_effects(
                    identity, include_fragments=self._literal_statement_scopes is None)
                for identity in references):
            if self._short_circuiting:
                # A read-only argument says nothing about its opaque
                # consumer: that call can still mutate captured heap state.
                raise SQLFlowLimit('SQL generator consumer effects are unresolved; analysis is incomplete')
            # Known hash consumers can dispatch key callbacks even when the
            # generator itself has no SQL effects. Aliases keep this opaque
            # cursor boundary; the direct modeled consumers above are unchanged.
            self.check_collection_constructor(node)
            # An exhausted argument does not prove an opaque consumer inert:
            # the call itself may rewrite captured SQL without iterating it.
            # Only a direct native set.update with an exact set receiver and
            # exclusively exhausted generator inputs has no possible callback
            # here. May-call capability tags cannot authorize this exception.
            inert_update = (isinstance(node.func, ast.Attribute) and node.func.attr == 'update'
                            and self.value_kind(node.func.value)[0] == 'set'
                            and not node.keywords and len(arguments) == len(node.args)
                            and not any(isinstance(argument, ast.Starred) for argument in node.args)
                            and all(self.generator_phases.get(identity) == frozenset({'done'})
                                    for identity in references))
            # Retain the ordinary opaque-consumer boundary otherwise: later
            # modeled consumption must refuse instead of certifying the call.
            for identity in references:
                if not inert_update:
                    self.generator_phases[identity] = frozenset({'partial'})
            self._evaluated_values[node] = (None, None, None, False, 'unknown')
            return True
        if arguments and not receiver and self.local_generator_consumer(node, arguments):
            return True
        raise SQLFlowLimit('SQL unknown generator consumer is unsupported; analysis is incomplete')

    def retained_generator_predicate(self, call, bindings):
        """Prove a read-only predicate cannot release finalizable elements.

        A direct generator over a caller-held exact list/tuple borrows its
        elements: the caller still owns the container when its iterator and
        generator frame are released. Only intrinsic Boolean predicates are
        admitted, so consumption cannot mutate that owner or invoke callbacks.
        Delayed cursors, temporary containers and nested clauses have no such
        lifetime proof. This does not authorize execution inside an effectful
        predicate, where a surrounding operation can change the owner.
        """
        if (self._short_circuiting or bindings.dynamic_namespace or bindings.builtin_namespace
                or bindings.reflective_member_writes):
            return False
        identity = call.args[0]
        if (not isinstance(identity, ast.GeneratorExp) or len(identity.generators) != 1
                or self.generator_refs(self.value_facts(identity)) != frozenset({identity})):
            return False
        clause = identity.generators[0]
        if (clause.is_async or clause.ifs or not isinstance(clause.target, ast.Name)
                or not isinstance(clause.iter, ast.Name)
                or self.value_kind(clause.iter)[0] not in {'list', 'tuple'}):
            return False

        def intrinsic(expression):
            self.step()
            if isinstance(expression, ast.Constant):
                return True
            if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
                return intrinsic(expression.operand)
            if isinstance(expression, ast.BoolOp):
                return all(intrinsic(value) for value in expression.values)
            if not isinstance(expression, ast.Compare) or len(expression.ops) != 1:
                return False
            left, right = expression.left, expression.comparators[0]
            if not isinstance(left, (ast.Name, ast.Constant)):
                return False
            if isinstance(expression.ops[0], (ast.Is, ast.IsNot)):
                return isinstance(right, (ast.Name, ast.Constant))
            return (isinstance(expression.ops[0], (ast.In, ast.NotIn))
                    and isinstance(right, (ast.List, ast.Tuple)) and not right.elts)

        return intrinsic(identity.elt)

    def check_generator_callback_writes(self):
        """Do not ignore lexical writes behind helper or protocol dispatch.

        The eager engine models walrus stores, but an unresolved helper,
        property, operator or iterator callback can also replace a captured
        SQL binding. A declaration alone is not a write. Until such calls
        have a transfer summary, conservatively refuse a possible writer
        of this scope's live cells, even if its dispatch cannot be resolved.
        """
        cache = self._ownership_syntax
        if 'generator_callback_writes' not in cache:
            writes = set()
            for scope in self.ownership_bindings().owner_scopes.values():
                self.step()
                writes.update(set(scope['names']) & scope['capture_barriers'])
            cache['generator_callback_writes'] = frozenset(writes)
        if cache['generator_callback_writes'].intersection(self.value_risks):
            raise SQLFlowLimit('SQL generator callback writes are unresolved; analysis is incomplete')

    def generator_protocol_names(self):
        """Visible implicit dispatch, indexed once alongside lexical syntax."""
        cache = self._ownership_syntax
        if 'generator_protocol_names' not in cache:
            names = set(self.ownership_bindings().member_writes)
            for function in self.ownership_bindings().owner_scopes:
                self.step()
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.add(function.name)
                    if function.decorator_list:
                        names.add(f'property:{function.name}')
            cache['generator_protocol_names'] = frozenset(names)
        return cache['generator_protocol_names']

    def generator_database_fetch(self, call):
        """A DB-API result fetch following a modeled execution operation."""
        return (isinstance(call.func, ast.Attribute)
                and call.func.attr in {'fetchone', 'fetchmany', 'fetchall'}
                and not call.args and not call.keywords
                and isinstance(call.func.value, ast.Call)
                and bool(sql_sink_name(call.func.value, self.ownership_bindings())))

    def local_generator_consumer(self, call, arguments):
        """Apply a stable eager consumer in its own lexical frame.

        Only read-only generators and parameters used directly as loop inputs
        qualify. The callee cannot retain the cursor itself. Analyze its body
        with all possible yielded values, retaining its sinks and return facts;
        never substitute the caller's locals for the callee's lexical names.
        """
        target = self.ownership_call_target(call)
        if not target or target[0] != 'function':
            return False
        function = target[1]
        bindings = self.ownership_bindings()
        if (bindings.dynamic_namespace or '__code__' in bindings.member_writes
                or not isinstance(function, ast.FunctionDef)
                or function.decorator_list
                or function in self._consumer_calls
                or function.args.vararg or function.args.kwarg
                or any(isinstance(arg, ast.Starred) for arg in call.args)
                or any(keyword.arg is None for keyword in call.keywords)
                or any(not isinstance(default, ast.Constant) for default in function.args.defaults)
                or any(default is not None and not isinstance(default, ast.Constant)
                       for default in function.args.kw_defaults)):
            return False
        if function not in self._consumer_stable:
            references = [*bindings.name_loads.get(function.name, ()), *(node for node in bindings.scope_of
                          if isinstance(node, ast.Attribute) and node.attr == function.name)]
            stable = True
            for reference in references:
                self.step()
                if reference in bindings.direct_callees:
                    continue
                resolved = bindings.resolve(reference)
                if resolved and resolved[0] == 'function' and resolved[1] is function:
                    stable = False
                    break
            self._consumer_stable[function] = stable
        if not self._consumer_stable[function]:
            return False
        nodes = self.deferred_nodes(function)
        parents = {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)}
        if any(node is not function and isinstance(node, (
                ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
                ast.GeneratorExp, ast.Yield, ast.YieldFrom, ast.Await, ast.Global, ast.Nonlocal))
                or isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del))
                for node in nodes):
            return False
        local = set(bindings.owner_scopes[function]['names'])
        for node in nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in local:
                scope = bindings.scope_of.get(node)
                while scope is not None and scope['node'] is not function:
                    if node.id in scope['names']:
                        break
                    scope = scope['parent']
                if scope is not None and scope['node'] is not function:
                    continue
                resolved = bindings.resolve(node)
                if not resolved or resolved[0] not in {'unbound', 'import', 'function', 'class'}:
                    return False
                if resolved[0] == 'unbound' and not hasattr(builtins, node.id):
                    return False
                if (resolved[0] == 'function'
                        and not isinstance(bindings.owner_scopes[resolved[1]]['parent']['node'], ast.Module)):
                    return False
        record = {'positional': _positional_parameters(function), 'bound_receiver': target[2]}
        actual = _bind_call_arguments(call, record)
        positional = _positional_parameters(function)
        if target[2]:
            if not isinstance(call.func, ast.Attribute) or not positional:
                return False
            actual[positional[0]] = call.func.value
        for name, default in zip(positional[len(positional) - len(function.args.defaults):], function.args.defaults):
            actual.setdefault(name, default)
        for parameter, default in zip(function.args.kwonlyargs, function.args.kw_defaults):
            if default is not None:
                actual.setdefault(parameter.arg, default)
        if set(actual) != set(_all_parameters(function)):
            return False
        iterable_names = {name for name, value in actual.items()
                          if any(value is argument for argument, _ in arguments)}
        opaque_parameters = {name for name, value in actual.items() if name not in iterable_names
                             and (self.value_facts(value)[4] != 'static'
                                  or self.fact_kinds(self.value_facts(value))[0] in {'list', 'tuple', 'set', 'dict'})}
        for node in nodes:
            if not isinstance(node, ast.Name):
                continue
            self.step()
            parent = parents.get(node)
            if node.id in iterable_names and (not isinstance(node.ctx, ast.Load)
                    or not isinstance(parent, (ast.For, ast.comprehension)) or parent.iter is not node):
                return False
            if node.id in opaque_parameters and isinstance(node.ctx, ast.Load):
                expression = node
                while isinstance(parent, ast.Attribute) and parent.value is expression:
                    expression, parent = parent, parents.get(parent)
                # A cursor may be used as a recognized SQL receiver. Other
                # opaque parameters cannot be aliased, retained or mutated
                # by this bounded summary; it has no caller-heap transfer.
                if not (isinstance(parent, ast.Call) and parent.func is expression
                        and list(self.sql_arguments(parent))):
                    return False
        projected = {}
        for argument, refs in arguments:
            values = []
            for identity in refs:
                if identity is None or self.generator_has_writes_or_sinks(identity):
                    return False
                if self.generator_phases.get(identity) == frozenset({'done'}):
                    values.append((None, None, None, False, 'static'))
                    continue
                projection = self.flow_probe()
                projection._consumer_calls = self._consumer_calls | {function}
                facts, _ = projection.read_only_generator_projection(identity)
                if self.generator_refs(facts):
                    return False
                values.append(facts)
            projected[argument] = self.join_value_facts(*values)
        probe = self.flow_probe()
        state = list(probe.sql_state())
        for index in (0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14):
            state[index].clear()
        probe.restore_sql_state(tuple(state))
        probe._evaluated_values.clear()
        lexical, scope = [], bindings.owner_scopes[function]
        while scope is not None:
            lexical.append(scope['node'])
            scope = scope['parent']
        probe._generator_scope = tuple(reversed(lexical))
        probe.func_stack = [node for node in probe._generator_scope if isinstance(node, ast.FunctionDef)]
        probe._comprehension_locals.clear()
        probe._consumer_calls = self._consumer_calls | {function}
        probe._return_slot = '\0sql_return'
        for name, value in actual.items():
            facts = projected.get(value)
            probe.bind_value_facts([name], self.with_kinds(facts, 'tuple', self.fact_kinds(facts)[0])
                                   if facts is not None else self.value_facts(value))
        try:
            flow = probe.statements(function.body, probe.sql_state())
        finally:
            # A later unsupported effect must not discard already discovered
            # sinks in this callee from the parent's partial result.
            for identity, finding in probe._sink_risks.items():
                previous = self._sink_risks.get(identity)
                if previous is None or finding[0] == 'critical':
                    self._sink_risks[identity] = finding
        returned = []
        if flow.get('return') is not None:
            probe.restore_sql_state(flow['return'])
            returned.append(probe.value_facts(ast.Name(id=probe._return_slot, ctx=ast.Load())))
        if flow.get('normal') is not None:
            returned.append((None, None, None, False, 'static'))
        if not returned or any(self.generator_refs(facts) for facts in returned):
            return False
        for _, refs in arguments:
            for identity in refs:
                self.generator_phases[identity] = frozenset({'partial'})
        self.validated.clear()
        self._attribute_epoch = max(self._attribute_epoch, probe._attribute_epoch)
        self._evaluated_values[call] = self.join_value_facts(*returned)
        return True

    def closed_generator_builtin_binding(self, name):
        """Prove the native namespace before trusting a generator consumer.

        Read-only imports with direct audited calls cannot replace a builtin.
        Escaped namespaces, reflection, and member writes revoke this proof
        even when the call's bare name has no lexical assignment.
        """
        bindings = self.ownership_bindings()
        if (bindings.dynamic_namespace or bindings.reflective_member_writes
                or name in bindings.member_writes):
            return False
        if not bindings.builtin_namespace:
            return True
        cache = self._ownership_syntax
        if 'generator_builtin_imports' not in cache:
            closed = True
            allowed = {'builtins.' + builtin for builtin in {
                'min', 'max', 'sorted', 'sum', 'len', 'next', 'list', 'tuple',
                'set', 'frozenset', 'iter', 'str', 'repr', 'bool', 'id', 'type',
            }}
            for node in bindings.scope_of:
                self.step()
                if (isinstance(node, ast.Name) and node.id in {'__builtins__', '__import__', 'vars'}
                        or isinstance(node, ast.Attribute)
                        and node.attr in {'__builtins__', '__dict__', 'modules', 'import_module'}):
                    closed = False
                    break
                if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
                    target = bindings.resolve(node)
                    if target == ('import', 'builtins'):
                        member = bindings.parents.get(node)
                        if (not isinstance(member, ast.Attribute) or member not in bindings.direct_callees
                                or bindings.resolve(member) not in {('import', item) for item in allowed}):
                            closed = False
                            break
                    elif target and target[0] == 'import' and target[1].startswith('builtins.'):
                        if target[1] not in allowed or node not in bindings.direct_callees:
                            closed = False
                            break
            cache['generator_builtin_imports'] = closed
        return cache['generator_builtin_imports']

    def check_generator_reducer(self, facts, key, length_key, deferred_keys, *, yielded):
        """Prove implicit reducer dispatch from each actual yielded value.

        A read-only generator can still hand a reducer an object whose
        comparison, arithmetic or key protocols replace an enclosing query.
        Fresh list records may be keyed without comparing the lists, but
        neither their contents nor their destruction may dispatch callbacks.
        Checking at emission keeps empty/exhausted cursors free of callbacks.
        """
        shape = self.element_shape(self.fact_kinds(facts))
        has_key = key is not None and not (isinstance(key, ast.Constant) and key.value is None)
        if (has_key and isinstance(yielded, ast.List)
                and not any(isinstance(item, ast.Starred) for item in yielded.elts)
                and self.fact_kinds(facts)[0] == 'list'
                and self.hash_safe_shape(self.fact_kinds(facts)[1])):
            # A directly yielded list literal is private to the reducer.
            # Named/walrus-captured lists and mutable child elements cannot
            # borrow this proof: later generator steps may mutate aliases.
            shape = 'list', self.fact_kinds(facts)[1]
        elif not self.hash_safe_shape(shape):
            raise SQLFlowLimit('SQL generator reducer callbacks are unresolved; analysis is incomplete')
        if deferred_keys is not None:
            deferred_keys.add(shape)
        else:
            self.check_generator_reducer_key(shape, key, length_key)

    def generator_reducer_key_function(self, key):
        """Resolve a private, already defined key without calling opaque code.

        Only a direct same-scope name may borrow this proof. Every use must
        pass it to a binding-verified builtin reducer; an alias, export or
        reflective mutation could replace the function's code or captures.
        The cached part is syntax only. Definition order and branch presence
        remain live flow facts, checked separately on every consumption.
        """
        bindings = self.ownership_bindings()
        target = bindings.resolve(key) if isinstance(key, ast.Name) else None
        if (not target or target[0] != 'function' or target[2]
                or not isinstance(target[1], ast.FunctionDef)
                or key.id != target[1].name or bindings.dynamic_namespace
                or bindings.reflective_member_writes
                or {'__code__', '__globals__', '__defaults__', '__kwdefaults__'} & bindings.member_writes):
            return None
        function = target[1]
        owner = bindings.owner_scopes[function]['parent']
        if (owner is None or isinstance(owner['node'], ast.ClassDef)
                or not self._generator_scope or owner['node'] is not self._generator_scope[-1]
                or self.binding_sites.get(function) != frozenset({function})):
            return None
        cache = self._ownership_syntax.setdefault('reducer_key_functions', {})
        if function not in cache:
            cache[function] = None
            body = function.body
            if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:]
            if (function.decorator_list or len(body) != 1 or not isinstance(body[0], ast.Return)
                    or body[0].value is None):
                return None
            for reference in bindings.name_loads.get(function.name, ()):
                self.step()
                if bindings.lexical_owner(reference) is not owner:
                    continue
                keyword = bindings.parents.get(reference)
                call = bindings.parents.get(keyword)
                if (not isinstance(keyword, ast.keyword) or keyword.arg != 'key'
                        or keyword.value is not reference or not isinstance(call, ast.Call)):
                    return None
                consumer = bindings.resolve(call.func)
                name = (consumer[1] if consumer and consumer[0] == 'unbound' else
                        consumer[1].removeprefix('builtins.')
                        if consumer and consumer[0] == 'import'
                        and consumer[1] in {'builtins.min', 'builtins.max', 'builtins.sorted'} else '')
                if name not in {'min', 'max', 'sorted'} or not self.closed_generator_builtin_binding(name):
                    return None
            cache[function] = body[0].value
        expression = cache[function]
        return (function.args, expression) if expression is not None else None

    def check_generator_reducer_key(self, shape, key, length_key):
        """Prove a key expression without substituting generator locals.

        Only exact builtin operations are admitted; their result shape does
        not replace the original yielded value's SQL provenance. An unknown
        callback, comparison, coercion or cleanup remains incomplete.
        """
        if key is None or isinstance(key, ast.Constant) and key.value is None or length_key:
            return
        selected = ((key.args, key.body) if isinstance(key, ast.Lambda)
                    else self.generator_reducer_key_function(key))
        if selected is None:
            raise SQLFlowLimit('SQL generator reducer key callbacks are unresolved; analysis is incomplete')
        args, expression = selected
        parameters = (*args.posonlyargs, *args.args)
        if (len(parameters) != 1 or args.defaults or args.kwonlyargs
                or args.vararg is not None or args.kwarg is not None):
            raise SQLFlowLimit('SQL generator reducer key signature is unresolved; analysis is incomplete')

        def key_shape(value):
            self.step()
            if isinstance(value, ast.Name):
                if value.id == parameters[0].arg:
                    return shape
                # The comprehension's same-spelled local is a different
                # cell from this key's capture. Until that outer frame
                # is restored, do not certify its value from loop facts.
                owner = self.ownership_bindings().lexical_owner(value)
                if (value.id in self._comprehension_locals or owner is None
                        or not self._generator_scope or owner['node'] is not self._generator_scope[-1]):
                    return ''
                return self.element_shape(self.value_kind(ast.Name(id=value.id, ctx=ast.Load())))
            if isinstance(value, ast.Constant):
                return self.element_shape(self.value_kind(value))
            if isinstance(value, ast.Tuple):
                return 'tuple', self.join_element_shapes(*(key_shape(item) for item in value.elts))
            if isinstance(value, ast.UnaryOp):
                operand = key_shape(value.operand)
                if isinstance(value.op, ast.Not) and self.hash_safe_shape(operand):
                    return 'number'
                if operand == 'number' and isinstance(value.op, (ast.UAdd, ast.USub, ast.Invert)):
                    return 'number'
            if isinstance(value, ast.BinOp):
                left, right = key_shape(value.left), key_shape(value.right)
                if left == right == 'number':
                    return 'number'
                if isinstance(value.op, ast.Add) and left == right == 'str':
                    return 'str'
                if (isinstance(value.op, ast.Add) and isinstance(left, tuple) and isinstance(right, tuple)
                        and left[0] == right[0] == 'tuple'):
                    return 'tuple', self.join_element_shapes(left[1], right[1])
            if isinstance(value, ast.Subscript):
                container, index = key_shape(value.value), key_shape(value.slice)
                if index == 'number':
                    if container == 'str':
                        return 'str'
                    if isinstance(container, tuple) and container[0] in {'tuple', 'list'}:
                        return container[1]
            if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                    and value.func.id == 'len' and len(value.args) == 1 and not value.keywords
                    and not isinstance(value.args[0], ast.Starred)
                    and self.ownership_bindings().resolve(value.func) == ('unbound', 'len')
                    and self.closed_generator_builtin_binding('len')):
                argument = key_shape(value.args[0])
                if (argument == 'str' or isinstance(argument, tuple)
                        and argument[0] in {'tuple', 'list'}):
                    return 'number'
            return ''

        if not self.hash_safe_shape(key_shape(expression)):
            raise SQLFlowLimit('SQL generator reducer key callbacks are unresolved; analysis is incomplete')

    def local_list_effect_plan(self, call, epochs, enclosing_reads):
        """Borrow a private list through a stable local helper parameter."""
        if (not isinstance(call.func, ast.Name)
                or not (self.exclusive_lists or enclosing_reads or self._iterated_lists or self._argument_list_reads)):
            return None
        target = self.ownership_call_target(call)
        if (not target or target[0] != 'function'
                or target[1] in self._sealed_closures and self._sealed_closures[target[1]][0]):
            return None
        function = target[1]
        bindings = self.ownership_bindings()
        owner = bindings.owner_scopes[function]['parent']
        if (not isinstance(function, ast.FunctionDef) or not bindings.eager_function(function)
                or not self._generator_scope or owner is None or owner['node'] is not self._generator_scope[-1]
                or bindings.dynamic_namespace or bindings.builtin_namespace or function.decorator_list
                or function.args.vararg or function.args.kwarg
                or any(isinstance(arg, ast.Starred) for arg in call.args)
                or any(keyword.arg is None for keyword in call.keywords)
                or any(not isinstance(default, ast.Constant) for default in function.args.defaults)
                or any(default is not None and not isinstance(default, ast.Constant)
                       for default in function.args.kw_defaults)):
            return None
        actual = _bind_call_arguments(call, {'positional': _positional_parameters(function)})
        positional = _positional_parameters(function)
        for name, default in zip(positional[len(positional) - len(function.args.defaults):], function.args.defaults):
            actual.setdefault(name, default)
        for arg, default in zip(function.args.kwonlyargs, function.args.kw_defaults):
            if default is not None:
                actual.setdefault(arg.arg, default)
        if set(actual) != _all_parameters(function) or any(self.generator_refs(self.value_facts(v)) for v in actual.values()):
            return None
        contracts = self._ownership_syntax.setdefault('list_effect_contracts', {})
        if function not in contracts:
            nodes = self.deferred_nodes(function)
            local = set(bindings.owner_scopes[function]['names'])
            parameters = _all_parameters(function)
            allowed, mutated = set(parameters), set()
            free = {node.id for node in nodes if isinstance(node, ast.Name)
                    and isinstance(node.ctx, ast.Load)} - local
            parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
            valid = not any(reference not in bindings.direct_callees and bindings.resolve(reference) == target
                            for reference in bindings.name_loads.get(function.name, ()))
            for node in nodes:
                self.step()
                if (node is not function and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda))
                        or isinstance(node, (ast.GeneratorExp, ast.Global, ast.Nonlocal))):
                    valid = False
                if isinstance(node, ast.Call):
                    called = self.ownership_call_target(node, captured=False)
                    if called and called[0] == 'function' and called[1] in self._sealed_closures:
                        free.update(self._sealed_closures[called[1]][0])
                        free.update(self._sealed_closures[called[1]][2])
                if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in parameters:
                        mutated.add(node.value.id)
                    else:
                        valid = False
                if not (isinstance(node, ast.Name) and node.id in parameters):
                    continue
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    allowed.discard(node.id)
                    continue
                parent = parents.get(node)
                if isinstance(parent, ast.Subscript) and parent.value is node:
                    continue
                if isinstance(parent, ast.Attribute) and parent.value is node:
                    invoked = parents.get(parent)
                    if (parent.attr in {'append', 'extend', 'insert', '__setitem__', 'pop'}
                            and isinstance(invoked, ast.Call) and invoked.func is parent):
                        mutated.add(node.id)
                        continue
                if (isinstance(parent, ast.Call) and parent.args == [node] and not parent.keywords
                        and isinstance(parent.func, ast.Name) and parent.func.id in {'len', 'bool', 'id', 'type'}
                        and bindings.resolve(parent.func) == ('unbound', parent.func.id)):
                    continue
                if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
                    continue
                if isinstance(parent, (ast.If, ast.While, ast.IfExp)) and parent.test is node:
                    continue
                if isinstance(parent, ast.For) and parent.iter is node:
                    continue
                allowed.discard(node.id)
            contracts[function] = (frozenset(mutated), frozenset(free), valid and mutated.issubset(allowed))
        mutated, free, safe = contracts[function]
        if not mutated:
            return None
        names = {actual[name].id for name in mutated if isinstance(actual[name], ast.Name)}
        if any((scope, name) in enclosing_reads for scope in self._generator_scope for name in names):
            raise SQLFlowLimit('SQL list mutation during argument evaluation is unsupported; analysis is incomplete')
        if any((scope, name) in self._iterated_lists for scope in self._generator_scope for name in names):
            raise SQLFlowLimit('SQL mutation during list iteration is unsupported; analysis is incomplete')
        if not safe:
            if any(isinstance(actual[name], ast.Name) and actual[name].id in self.exclusive_lists for name in mutated):
                raise SQLFlowLimit('SQL list helper parameter escape is unresolved; analysis is incomplete')
            return None
        if any(self.value_kind(ast.Name(id=name, ctx=ast.Load()))[0] == 'list' for name in free):
            return None
        borrowed = {}
        for name in mutated:
            value = actual[name]
            if (not isinstance(value, ast.Name) or value.id not in self.exclusive_lists
                    or self.value_kind(value)[0] != 'list' or value not in epochs
                    or epochs[value][0] != self.validation_epoch(value)[0]):
                if isinstance(value, ast.Name) and any((scope, value.id) in self._argument_list_reads
                                                      for scope in self._generator_scope):
                    raise SQLFlowLimit('SQL list helper captured binding changed; analysis is incomplete')
                return None
            borrowed[name] = value
        roots = {value.id for value in borrowed.values()}
        if not borrowed:
            return None
        if len(roots) != len(borrowed):
            raise SQLFlowLimit('SQL list helper parameter aliases are unresolved; analysis is incomplete')
        if self.binding_sites.get(function) != frozenset({function}):
            raise SQLFlowLimit('SQL list helper definition order is unresolved; analysis is incomplete')
        for name, value in actual.items():
            if name in borrowed:
                continue
            pending = [value]
            while pending:
                node = pending.pop()
                self.step()
                if self.value_kind(node)[0] in {'str', 'number'}:
                    # A captured scalar cannot alias the list used to compute
                    # it: len(output) is a value, not another output borrow.
                    continue
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in roots:
                    raise SQLFlowLimit('SQL list helper parameter aliases are unresolved; analysis is incomplete')
                pending.extend(ast.iter_child_nodes(node))
        return function, actual, borrowed

    def local_list_effect_call(self, call, plan):
        function, actual, borrowed = plan
        incoming = self.sql_state()
        probe = self.flow_probe()
        probe._evaluated_values.clear()
        probe._return_slot = '\0sql_return'
        probe._generator_scope = (*self._generator_scope, function)
        probe.func_stack.append(function)
        probe._consumer_calls = self._consumer_calls | {function}
        probe._list_effect_active = True
        probe._list_effect_parameters = function, frozenset(borrowed)
        for name in self.ownership_bindings().owner_scopes[function]['names']:
            probe.bind_value_facts([name], (None, None, None, False, 'unknown'))
        for name, value in actual.items():
            probe.bind_value_facts([name], self.value_facts(value))
        probe.exclusive_lists.update(borrowed)
        try:
            flow = probe.statements(function.body, probe.sql_state())
        finally:
            for identity, finding in probe._sink_risks.items():
                previous = self._sink_risks.get(identity)
                if previous is None or finding[0] == 'critical':
                    self._sink_risks[identity] = finding
        def caller_store(state):
            mapped = self.flow_probe()
            mapped.restore_sql_state(incoming)
            probe.restore_sql_state(state)
            for parameter, value in borrowed.items():
                mapped.bind_value_facts([value.id], probe.value_facts(ast.Name(id=parameter, ctx=ast.Load())))
                mapped.binding_sites[value.id] = incoming[12].get(value.id, frozenset({None}))
                if parameter in state[10]:
                    mapped.exclusive_lists.add(value.id)
            mapped.validated.intersection_update(state[8])
            return mapped.sql_state()
        normal = self.join_sql_states(flow.get('normal'), flow.get('return'))
        if 'raise' in flow:
            self._pending_raise = self.join_sql_states(self._pending_raise, caller_store(flow['raise']))
        if normal is None:
            raise SQLNoNormalReturn()
        self.restore_sql_state(caller_store(normal))
        self.invalidate_validation(value.id for value in borrowed.values())
        self._attribute_epoch = max(self._attribute_epoch, probe._attribute_epoch)
        returned = []
        if flow.get('return') is not None:
            probe.restore_sql_state(flow['return'])
            returned.append(probe.value_facts(ast.Name(id=probe._return_slot, ctx=ast.Load())))
        if 'normal' in flow:
            returned.append((None, None, None, False, 'static'))
        if any(self.generator_refs(facts) for facts in returned):
            raise SQLFlowLimit('SQL helper generator escape is unsupported; analysis is incomplete')
        self._evaluated_values[call] = self.join_value_facts(*returned)
        return True

    def literal_list_index(self, value):
        # Python represents -1/+1 as unary expressions, not Constant nodes.
        # These exact integer operations cannot run an overloaded __index__
        # or arithmetic callback. Unknown expressions retain the refusal path.
        while isinstance(value, ast.UnaryOp) and isinstance(value.op, (ast.UAdd, ast.USub)):
            self.step()
            value = value.operand
        return isinstance(value, ast.Constant) and type(value.value) is int

    def list_update(self, node):
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        if (receiver is not None and node.func.attr == 'pop' and self.borrowed_child_read(receiver)
                and self.fact_kinds(self.value_facts(receiver))[1] not in {'str', 'number'}):
            raise SQLFlowLimit('SQL list helper child aliases are unresolved; analysis is incomplete')
        numeric = self.numeric_reference(receiver) if receiver is not None else None
        if (numeric is not None and node.func.attr in {'append', 'extend', 'insert', '__setitem__', 'pop'}
                and not node.keywords and not any(isinstance(arg, ast.Starred) for arg in node.args)):
            indexed = node.func.attr in {'insert', '__setitem__'}
            arity = 2 if indexed else 0 if node.func.attr == 'pop' else 1
            if len(node.args) != arity or indexed and not self.literal_list_index(node.args[0]):
                raise SQLFlowLimit('SQL numeric list call shape is unresolved; analysis is incomplete')
            if node.func.attr == 'pop':
                if self.record_fields(numeric) and numeric[1] == 1:
                    raise SQLFlowLimit('SQL record length mutation is unsupported; analysis is incomplete')
                depth = numeric[1] - 1
                facts = self.with_kinds(self.value_facts(receiver), 'list' if depth else 'number',
                                        '' if self.record_fields(numeric) and depth == 1 else
                                        'number' if depth == 1 else 'list' if depth else '')
                self._evaluated_values[node] = (self.with_numeric_reference(facts, (numeric[0], depth))
                                                if depth else facts)
            else:
                self.numeric_mutation(receiver, node.args[-1], extending=node.func.attr == 'extend')
                self.widen_numeric_region(numeric, self.value_facts(node.args[-1]))
                self._evaluated_values[node] = (None, None, None, False, 'static')
            return True
        if (isinstance(node.func, ast.Attribute) and node.func.attr == 'pop'
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in self.exclusive_lists
                and not node.keywords
                and (not node.args or len(node.args) == 1 and self.literal_list_index(node.args[0]))
                and not self.generator_refs(self.value_facts(node.func.value))):
            # A builtin list pop does not export the list itself. The returned
            # element still carries its SQL facts. Keep the receiver's may
            # contents conservatively: order/length are not tracked, so a pop
            # cannot prove that every unsafe element has been removed.
            self._evaluated_values[node] = self.iteration_facts(node.func.value)
            return True
        if not (isinstance(node.func, ast.Attribute) and node.func.attr in {'append', 'extend', 'insert', '__setitem__'}
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in self.exclusive_lists
                and len(node.args) == (2 if node.func.attr in {'insert', '__setitem__'} else 1)
                and not node.keywords and not any(isinstance(arg, ast.Starred) for arg in node.args)):
            return False
        if node.func.attr in {'insert', '__setitem__'} and not self.literal_list_index(node.args[0]):
            return False
        argument = node.args[-1]
        if (self._generator_scope[-1], node.func.value.id) in self._argument_list_reads:
            raise SQLFlowLimit('SQL list mutation during argument evaluation is unsupported; analysis is incomplete')
        references = self.generator_refs(self.value_facts(argument))
        if None in references or references and node.func.attr != 'extend':
            return False
        if (self._generator_scope and (self._generator_scope[-1], node.func.value.id) in self._iterated_lists
                and (references or any(self.value_facts(argument)[:3]))):
            # An iterator observes future writes, not a construction-time
            # snapshot. Until heap iteration has an object-identity summary,
            # do not silently drop SQL appended during that same iteration.
            raise SQLFlowLimit('SQL mutation during list iteration is unsupported; analysis is incomplete')
        # Only a proved, unescaped builtin list authorizes this consumer;
        # arbitrary .extend look-alikes and escaped aliases still refuse.
        name = node.func.value.id
        before = self.value_facts(node.func.value)
        before_sites = self.binding_sites.get(name, frozenset({None}))
        produced = (self.value_facts(argument) if node.func.attr != 'extend' else
                    self.materialize_generators(references, consumer_can_raise=True) if references else
                    self.iteration_facts(argument))
        combined = self.join_value_facts(before, produced)
        old_element = self.fact_kinds(before)[1]
        new_element = self.element_shape(self.fact_kinds(produced))
        facts = self.with_kinds(combined, 'list', self.join_element_shapes(old_element, new_element))
        after_sites = self.binding_sites.get(name, frozenset({None}))
        if before_sites & after_sites:
            if before_sites != after_sites:
                # Some paths rebound the name, others still refer to the old
                # receiver. Retain both stores instead of cleaning either one.
                current = self.value_facts(ast.Name(id=name, ctx=ast.Load()))
                facts = self.join_value_facts(facts, current)
            self.bind_value_facts([name], facts)
            self.binding_sites[name] = after_sites
            if before_sites == after_sites:
                self.exclusive_lists.add(name)
        # Otherwise every path rebound the name during iteration. Mutation of
        # the old, previously exclusive receiver cannot overwrite that binding.
        self._evaluated_values[node] = (None, None, None, False, 'static')
        return True

    def generator_has_sql_effects(self, identity, *, include_fragments=True):
        """Inspect projected values without consuming the actual cursor.

        The iterable's construction arguments are not its yielded values.
        For example, ``None for row in [unsafe_query]`` never exports the
        query. Reuse the bounded evaluator on private flow state so lexical
        captures, filters and generator-local bindings retain their normal
        semantics. Writes and SQL sinks still require a modeled consumer.
        A proven literal-only SQL inventory cannot use projected values as
        fragments; its opaque consumers still cannot export complete SQL text.
        """
        if identity not in self._generator_specs or self.generator_has_writes_or_sinks(identity):
            return True
        before = self.sql_state()
        facts, probe = self.generator_projection(identity)
        return (any(facts[:3] if include_fragments else facts[:1]) or bool(self.generator_refs(facts))
                or self.generator_changes_sql_state(identity, before, probe))

    @staticmethod
    def generator_changes_sql_state(identity, before, probe):
        after = probe.sql_state()
        # Projection completes this cursor only in private state. Consuming
        # another captured cursor is an observable effect, however: a later
        # drain must not restart it or lose an earlier prefix's SQL values.
        phases_before = {key: value for key, value in before[7].items() if key is not identity}
        # Inner generator expressions allocate private cursors while this
        # projection runs. They are not mutations of an enclosing cursor;
        # their exports/effects are checked by their own consumer path.
        phases_after = {key: after[7].get(key) for key in phases_before}
        return (any(before[index] != after[index] for index in (0, 1, 2, 3, 4, 5, 9))
                or phases_before != phases_after or bool(probe._sink_risks))

    def read_only_generator_projection(self, identity):
        before = self.sql_state()
        facts, probe = self.generator_projection(identity)
        if self.generator_changes_sql_state(identity, before, probe):
            raise SQLFlowLimit('SQL partial generator effects are unsupported; analysis is incomplete')
        return facts, probe

    def flow_probe(self):
        """Independent flow stores with shared bounded analysis and syntax indexes."""
        probe = SQLInjectionAnalyzer(
            self.text, self.lines, self.param_names, self.name_risk,
            self.sanitizers, self.sanitizer_summaries, budget=self._budget,
            bindings=self.bindings)
        probe.restore_sql_state(self.sql_state())
        probe._evaluated_values = self._evaluated_values.copy()
        probe._evaluated_call_targets = self._evaluated_call_targets.copy()
        probe._evaluated_comparison_truths = self._evaluated_comparison_truths.copy()
        probe._indexed_receivers = self._indexed_receivers.copy()
        probe._generator_specs = self._generator_specs.copy()
        probe._generator_running = self._generator_running.copy()
        probe._generator_scope = self._generator_scope
        probe._short_circuiting = self._short_circuiting
        probe._completed_predicates = self._completed_predicates.copy()
        # These tables contain lexical syntax only. Sharing their immutable
        # entries avoids charging the same scope walk again in independent
        # projections; live SQL facts and ownership above remain private.
        probe._builtin_bindings = self._builtin_bindings
        probe._list_captures = self._list_captures
        probe._deferred_name_cache = self._deferred_name_cache
        probe._deferred_node_cache = self._deferred_node_cache
        probe._ownership_bindings = self._ownership_bindings
        probe._ownership_syntax = self._ownership_syntax
        probe._nonretaining_parameters = self._nonretaining_parameters
        probe._consuming_iterables = self._consuming_iterables.copy()
        probe._iterated_lists = self._iterated_lists.copy()
        probe._sealed_closures = self._sealed_closures.copy()
        probe._closure_groups = self._closure_groups.copy()
        probe._closure_list_writes = self._closure_list_writes.copy()
        probe._closure_cell_writes = self._closure_cell_writes.copy()
        probe._comprehension_locals = self._comprehension_locals.copy()
        probe._consumer_calls = self._consumer_calls
        probe._facade_calls = self._facade_calls
        probe._facade_results = self._facade_results.copy()
        probe._list_effect_active = self._list_effect_active
        probe._list_effect_parameters = self._list_effect_parameters
        probe._consumer_stable = self._consumer_stable
        probe._string_returns = self._string_returns
        probe._recursive_closures = self._recursive_closures
        probe._closure_worklist = self._closure_worklist
        probe._argument_list_reads = self._argument_list_reads.copy()
        probe._retired_numeric_regions = self._retired_numeric_regions
        probe._numeric_literal_shapes = self._numeric_literal_shapes
        probe._suppression_index = self._suppression_index
        probe._binding_epochs = self._binding_epochs.copy()
        probe._attribute_epoch = self._attribute_epoch
        probe.func_stack = self.func_stack.copy()
        probe.sink_lineno = self.sink_lineno
        return probe

    def generator_projection(self, identity):
        """Bounded private projection; never alter the real cursor or store."""
        probe = self.flow_probe()
        # Relevance includes every possible remaining yield, even when an
        # earlier opaque consumer advanced an unknown prefix. This is only
        # a probe; the actual cursor stays partial and cannot be restarted.
        probe.generator_phases[identity] = frozenset({'fresh'})
        try:
            facts = probe.materialize_generators(frozenset({identity}))
        except SQLNoNormalReturn as exc:
            # A hypothetical drain need not return, but an opaque consumer
            # may not iterate at all. It cannot erase the caller's successor.
            raise SQLFlowLimit('SQL generator projection completion is unresolved; analysis is incomplete') from exc
        return facts, probe

    def generator_has_writes_or_sinks(self, identity):
        deferred = [identity.elt]
        deferred.extend(condition for generator in identity.generators for condition in generator.ifs)
        deferred.extend(generator.iter for generator in identity.generators[1:])
        bindings = self.ownership_bindings()
        for expression in deferred:
            for child in ast.walk(expression):
                if isinstance(child, ast.NamedExpr):
                    return True
                if not isinstance(child, ast.Call):
                    continue
                if (call_name(child.func).rsplit('.', 1)[-1] in EXECUTE_METHODS | {'extra'}
                        or sql_sink_name(child, bindings)):
                    return True
                target = bindings.resolve(child.func)
                if (target and target[0] == 'function'
                        and target[1] in bindings.local_sql_effects()):
                    # A scalar helper can forward a dynamically built query
                    # under any spelling. A private read-only projection must
                    # not discard the sink reached with its actual inputs.
                    return True
        return False

    def visit_Assert(self, node):
        optimized = self.sql_state()
        try:
            self.visit(node.test)
        except SQLNoNormalReturn:
            self.restore_sql_state(optimized)
            return {'normal': optimized}
        incoming = self.sql_state()
        truth = self.condition_truth(node.test)
        if truth is not True:
            if node.msg is not None:
                try:
                    self.visit(node.msg)
                    self.retire_numeric_arguments([node.msg])
                except SQLNoNormalReturn:
                    self.restore_sql_state(optimized)
                    return {'normal': optimized}
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
                    try:
                        self.visit(handler.type)
                    except SQLNoNormalReturn:
                        # Earlier handlers may already have matched. Failure
                        # to evaluate this type cannot erase their exits or
                        # skip finally; it only prevents later handlers.
                        break
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
            try:
                self.visit(item.context_expr)
            except SQLNoNormalReturn:
                if not index:
                    raise
                # Already-entered managers can suppress an exception from
                # evaluating a later context expression. Its body is never
                # entered, but the statement can still complete normally.
                normal = self.join_sql_states(suppressed_setup, before, self._pending_raise)
                self.restore_sql_state(normal)
                return {'normal': normal}
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

    def pattern_bindings(self, pattern, facts):
        """Project matched values, rather than their container, into captures."""
        self.step()
        if isinstance(pattern, ast.MatchAs):
            bindings = [(pattern.name, facts)] if pattern.name else []
            if pattern.pattern is not None:
                bindings.extend(self.pattern_bindings(pattern.pattern, facts))
            return bindings
        if isinstance(pattern, ast.MatchStar):
            return ([(pattern.name, self.with_kinds(facts, 'list', self.fact_kinds(facts)[0]))]
                    if pattern.name else [])
        if isinstance(pattern, ast.MatchSequence):
            element = self.element_facts(facts)
            return [binding for child in pattern.patterns for binding in self.pattern_bindings(child, element)]
        if isinstance(pattern, ast.MatchMapping):
            bindings = [(pattern.rest, self.with_kinds(facts, 'dict'))] if pattern.rest else []
            for child in pattern.patterns:
                bindings.extend(self.pattern_bindings(child, self.with_kinds(facts, '')))
            return bindings
        if isinstance(pattern, ast.MatchClass):
            return [binding for child in (*pattern.patterns, *pattern.kwd_patterns)
                    for binding in self.pattern_bindings(child, self.with_kinds(facts, ''))]
        if isinstance(pattern, ast.MatchOr):
            alternatives = {}
            for child in pattern.patterns:
                for name, value in self.pattern_bindings(child, facts):
                    alternatives.setdefault(name, []).append(value)
            return [(name, self.join_value_facts(*values)) for name, values in alternatives.items()]
        return []

    def visit_Match(self, node):
        # Each arm has an independent incoming store. Without value/type
        # resolution, refutable patterns may miss; only an unguarded
        # capture/wildcard consumes all remaining subjects.
        self.visit(node.subject)
        # Capture patterns may alias the subject. Keep this invalidation in
        # the flow-aware visitor; generic traversal would execute alternatives
        # sequentially and let a later arm erase an earlier arm's SQL risk.
        self.escape_lists([node.subject])
        incoming = self.sql_state()
        subject_facts = self.value_facts(node.subject)
        flow, exhaustive = {}, False
        for case in node.cases:
            self.step()
            self.restore_sql_state(incoming)
            for name, facts in self.pattern_bindings(case.pattern, subject_facts):
                self.bind_value_facts([name], facts)
            truth = None
            if case.guard is not None:
                try:
                    self.visit(case.guard)
                except SQLNoNormalReturn:
                    if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None:
                        exhaustive = True
                        break
                    # Refutable patterns can miss before their guard runs.
                    # Keep that incoming store for later arms/the successor.
                    continue
                truth = self.condition_truth(case.guard)
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
        """Traverse value contributors, excluding lookup keys and indexes."""
        yield node
        if node in self._evaluated_values:
            return
        if isinstance(node, ast.Subscript):
            # Index expressions execute, but they select the value rather
            # than becoming part of its SQL text. visit_Subscript already
            # accounts for eager index effects and exceptions.
            yield from self.value_nodes(node.value)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
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
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            for sequence, count in ((node.left, node.right), (node.right, node.left)):
                if (self.value_kind(sequence)[0] in {'list', 'tuple', 'str'}
                        and self.value_kind(count)[0] == 'number'):
                    # Intrinsic repetition copies the sequence's values; the
                    # integer count never becomes returned text. Its eager
                    # calls and SQL sinks were still visited independently.
                    return self.classify_expr(sequence)
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
            kind, _ = self.value_kind(node.left)
            if kind in {'list', 'tuple', 'number'} and kind == self.value_kind(node.right)[0]:
                # Exact builtin collections concatenate their elements; they
                # do not interpolate SQL. Numeric addition produces no text.
                # The normal value walk still retains both operands' SQL.
                return None
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
        return (looks_like_sql(node) or any(
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
            facts = self._evaluated_values[value]
            if (isinstance(value, ast.Name) and self.fact_kinds(facts)[0] == 'list'
                    and self.fact_kinds(facts)[1] != '' and value.id not in self.exclusive_lists
                    and self.numeric_fact_reference(facts) is None):
                facts = self.with_kinds(facts, 'list')
            reference = self.numeric_fact_reference(facts)
            if reference is not None and (reference[0] not in self.numeric_regions
                                           or reference[0] in self._retired_numeric_regions):
                return self.with_numeric_reference(self.with_kinds(facts, 'list'), reference)
            return facts
        facts = (self.sql_risk(value), self.sql_risk(value, require_sql=False),
                 self.select_risk(value), self.has_sql_template(value), self.classify_expr(value),
                 self.generator_bindings.get(value.id, frozenset()) if isinstance(value, ast.Name) else frozenset(),
                 *self.value_kind(value))
        reference = self.numeric_lists.get(value.id) if isinstance(value, ast.Name) else None
        return self.with_numeric_reference(facts, reference) if reference is not None else facts

    def value_kind(self, value):
        """Exact shapes, plus negative-only set/update may-call capabilities."""
        if value in self._evaluated_values:
            return self.fact_kinds(self.value_facts(value))
        if isinstance(value, ast.Name):
            reference = self.numeric_lists.get(value.id)
            if reference is not None:
                if reference[0] in self.numeric_regions and reference[0] not in self._retired_numeric_regions:
                    return 'list', ('' if self.record_fields(reference) else 'number') if reference[1] == 1 else 'list'
                return 'list', ''
            pair = self.value_kinds.get(value.id, ('', ''))
            if (pair[0] == 'list' and pair[1] != ''
                    and value.id not in self.exclusive_lists):
                return 'list', ''
            if (value.id not in self.value_risks
                    and self.ownership_bindings().resolve(value) in {
                        ('unbound', 'set'), ('import', 'builtins.set')}):
                return frozenset({'constructor'}), ''
            return pair
        if (isinstance(value, ast.Attribute)
                and self.ownership_bindings().resolve(value) in {
                    ('unbound', 'set'), ('import', 'builtins.set')}):
            return frozenset({'constructor'}), ''
        if isinstance(value, ast.Constant):
            if value.value is None:
                return 'none', ''
            if type(value.value) in {bool, int, float, complex}:
                return 'number', ''
            if isinstance(value.value, str):
                return 'str', 'str'
            return '', ''
        if (isinstance(value, ast.JoinedStr)
                and (len(value.values) != 1 or isinstance(value.values[0], ast.Constant)
                     or isinstance(value.values[0], ast.FormattedValue)
                     and self.value_kind(value.values[0].value)[0] in {'str', 'number'})):
            # Combining multiple formatted/literal pieces constructs an exact
            # builtin string. A lone formatted value may return a str subclass
            # from __format__, unless the formatted operand itself is proved
            # an exact builtin primitive. Unknown operands retain that refusal.
            # The visitor still evaluates every formatter and its SQL effects.
            return 'str', 'str'
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            element = self.join_element_shapes(*(self.element_shape(self.value_kind(item)) for item in value.elts))
            return ('list' if isinstance(value, ast.List) else
                    'tuple' if isinstance(value, ast.Tuple) else 'set'), element
        if isinstance(value, ast.BinOp):
            left, right = self.value_kind(value.left), self.value_kind(value.right)
            if (isinstance(value.op, ast.Add) and left[0] == right[0]
                    and left[0] in {'list', 'tuple', 'number', 'str'}):
                return left[0], self.join_element_shapes(left[1], right[1])
            if (left[0] == right[0] == 'number'
                    and isinstance(value.op, (ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
                                               ast.Pow, ast.LShift, ast.RShift, ast.BitOr,
                                               ast.BitXor, ast.BitAnd))):
                # Exact builtin numeric operands cannot dispatch to a user's
                # arithmetic methods. An invalid combination may raise, but
                # successful completion still returns a builtin number.
                return 'number', ''
            if isinstance(value.op, ast.Mult):
                for sequence, count in ((left, right), (right, left)):
                    if sequence[0] in {'list', 'tuple', 'str'} and count[0] == 'number':
                        # Repetition retains may-contents and element shape;
                        # it does not turn the elements into the count. A
                        # float/complex count raises rather than invoking an
                        # unknown __index__ callback.
                        return sequence
        if (isinstance(value, ast.UnaryOp) and isinstance(value.op, (ast.UAdd, ast.USub))
                and self.value_kind(value.operand)[0] == 'number'):
            return 'number', ''
        return '', ''

    def iteration_facts(self, value):
        if (self.borrowed_child_read(value) and self.fact_kinds(self.value_facts(value))[1] not in {'str', 'number'}):
            raise SQLFlowLimit('SQL list helper child aliases are unresolved; analysis is incomplete')
        numeric = self.numeric_reference(value)
        if numeric is not None and numeric[1] > 1:
            # An iterator/comprehension can export child aliases without a
            # direct indexed binding. Until that transfer carries identities,
            # retire the region rather than preserving a stale leaf type.
            self.retire_numeric_region(numeric[0])
            raise SQLFlowLimit('SQL numeric list iterator aliases are unsupported; analysis is incomplete')
        facts = self.value_facts(value)
        if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id == 'enumerate' and self.builtin_is_unshadowed('enumerate')
                and not self.ownership_bindings().dynamic_namespace
                and not self.ownership_bindings().builtin_namespace
                and 'enumerate' not in self.ownership_bindings().member_writes
                and len(value.args) in {1, 2}
                and all(keyword.arg == 'start' for keyword in value.keywords)
                and len(value.keywords) <= 1 and not (len(value.args) == 2 and value.keywords)
                and not any(isinstance(argument, ast.Starred) for argument in value.args)
                and not self.generator_refs(self.value_facts(value.args[0]))):
            # enumerate validates start through the integer-index protocol
            # and yields fresh integers independently of the element's SQL
            # contents. Start's eager effects have already run. Do not give
            # the index the element's taint while destructuring the pair.
            item = self.iteration_facts(value.args[0])
            index = self.with_kinds((None, None, None, False, 'static'), 'number')
            pair = self.with_kinds(self.join_value_facts(index, item), 'tuple')
            return (*pair, (index, item))
        if (numeric is None and self.fact_kinds(facts)[0] == 'list' and self.fact_kinds(facts)[1] != ''
                and not (isinstance(value, ast.Name) and value.id in self.exclusive_lists
                         or isinstance(value, ast.List))):
            # Immutable initial elements do not freeze a mutable outer list.
            # Escaped storage may now hold callbacks, even if it held only
            # strings, numbers or tuples before. Do not project stale types.
            facts = self.with_kinds(facts, 'list')
        return self.element_facts(facts)

    def bind_value_facts(self, names, facts):
        if (self._generator_scope and self._generator_scope[-1] in self._sealed_closures
                and self._closure_cell_writes.get(self._generator_scope[-1], frozenset()).intersection(names)
                and (self.fact_kinds(facts)[0] not in {'number', 'str', 'none', 'scalar'}
                     or self.generator_refs(facts))):
            if self.set_update_capabilities(self.fact_kinds(facts)[0]):
                raise SQLFlowLimit('SQL collection key callbacks through a closure cell are unresolved; analysis is incomplete')
            raise SQLFlowLimit('SQL closure cell alias is unresolved; analysis is incomplete')
        self.invalidate_validation(names)
        risk, fragment_risk, select_risk, template, provenance = facts[:5]
        self.store_sql_risk(names, risk)
        for name in names:
            self.exclusive_lists.discard(name)
            self.numeric_lists.pop(name, None)
            reference = self.numeric_fact_reference(facts)
            if reference is not None:
                self.numeric_lists[name] = reference
            self.binding_sites[name] = frozenset({self._binding_site})
            references = self.generator_refs(facts)
            if references:
                self.generator_bindings[name] = references
            else:
                self.generator_bindings.pop(name, None)
            self.value_risks[name] = provenance
            kinds = self.fact_kinds(facts)
            if kinds != ('', ''):
                self.value_kinds[name] = kinds
            else:
                self.value_kinds.pop(name, None)
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
        facts = self.value_facts(value)
        references = self.generator_refs(facts)
        if isinstance(target, (ast.Tuple, ast.List)) and references:
            # Unpacking consumes the iterator; it does not bind every scalar
            # target to the generator object. Arity errors may stop early, so
            # deferred stores/sinks need a prefix model before we can accept
            # them. Read-only projections conservatively join yielded values.
            if any(identity is None or self.generator_has_writes_or_sinks(identity) for identity in references):
                raise SQLFlowLimit('SQL generator unpacking effects are unsupported; analysis is incomplete')
            self.note_possible_raise()
            facts = self.materialize_generators(references)
            # These are the yielded values already, not a container whose
            # element kind should be projected a second time.
            facts = self.with_kinds(facts, 'tuple', self.fact_kinds(facts)[0])
        return self.unpacking_bindings(target, facts)

    def unpacking_bindings(self, target, facts):
        """Unpacking projects elements; it cannot preserve a container type.

        Exact positional literals are handled by assignment_bindings above.
        For a dynamic iterable retain may-flow SQL facts, but only its proved
        homogeneous element shape. Deeper levels lose unknown element types;
        a starred target always collects a fresh list.
        """
        if isinstance(target, (ast.Tuple, ast.List)):
            if (len(facts) > 8 and len(facts[8]) == len(target.elts)
                    and not any(isinstance(item, ast.Starred) for item in target.elts)):
                return [binding for item, projected in zip(target.elts, facts[8])
                        for binding in self.unpacking_bindings(item, projected)]
            projected = self.element_facts(facts)
            return [binding for item in target.elts
                    for binding in self.unpacking_bindings(item, projected)]
        if isinstance(target, ast.Starred):
            facts = self.with_kinds(facts, 'list', self.fact_kinds(facts)[0])
            return self.unpacking_bindings(target.value, facts)
        return [(target, facts)]

    def store_assignment(self, target, facts):
        """Evaluate a target at its store point, after capturing RHS values.

        A subscript is an object write, not a discarded scalar binding. Loop
        and comprehension targets use exactly the same store semantics as
        assignments, including exceptions and left-to-right target effects.
        """
        self.visit(target)
        self.check_facade_store(target, facts)
        if isinstance(target, ast.Subscript):
            self.store_list_item(target, facts)
        else:
            self.bind_value_facts(binding_target_names(target), facts)

    def check_facade_store(self, target, facts):
        if facts[0] is None:
            return
        bindings = self.ownership_bindings()
        function = bindings.function_owner(target)
        if function not in bindings.sql_facade_flow()[0]:
            return
        if (isinstance(target, ast.Attribute)
                or isinstance(target, ast.Subscript) and self.value_kind(target.value)[0] != 'list'
                or isinstance(target, ast.Name) and target.id in bindings.owner_scopes[function]['capture_barriers']):
            raise SQLFlowLimit('SQL facade heap or closure store is unresolved; analysis is incomplete')

    def store_list_item(self, target, facts):
        """Join possible contents of a private builtin list on item writes.

        No element index/length facts are available, so replacing one or many
        elements is a weak update. Existing scalar reads keep their snapshots.
        Aliased receivers and generator objects still need heap identities;
        they cannot be accepted by silently dropping a write.
        """
        numeric = self.numeric_reference(target.value)
        if numeric is not None:
            # Preserve the region invariant before the ordinary aliased-list
            # fallback. A nonnumeric write must not leave stale numeric facts
            # on a parent stack or on another alias to this same nested list.
            fields = self.record_fields(numeric)
            if fields is not None and numeric[1] == 1:
                if isinstance(target.slice, ast.Slice):
                    raise SQLFlowLimit('SQL record slice mutation is unsupported; analysis is incomplete')
                expected = self.record_element_kind(numeric, target.slice)
                if (self.fact_kinds(facts)[0] != expected or any(facts[:3])
                        or self.generator_refs(facts) or expected == 'str' and facts[4] != 'static'):
                    raise SQLFlowLimit('SQL record field mutation is unresolved; analysis is incomplete')
                self.widen_numeric_region(numeric, facts)
                return
            expected = numeric[1] if isinstance(target.slice, ast.Slice) else numeric[1] - 1
            if (any(facts[:3]) or self.generator_refs(facts)
                    or self.fact_kinds(facts)[0] != ('number' if expected == 0 else 'list')):
                raise SQLFlowLimit('SQL nested numeric list mutation is unresolved; analysis is incomplete')
            if expected:
                raise SQLFlowLimit('SQL nested numeric list replacement is unsupported; analysis is incomplete')
            self.widen_numeric_region(numeric, facts)
            return
        if self.value_kind(target.value)[0] != 'list':
            return
        if self.generator_refs(facts):
            raise SQLFlowLimit('SQL list mutation stores a generator; analysis is incomplete')
        sites, owned = self._indexed_receivers.get(target, (frozenset({None}), False))
        if not (isinstance(target.value, ast.Name) and owned
                and target.value.id in self.exclusive_lists
                and sites == self.binding_sites.get(target.value.id, frozenset({None}))):
            if any(facts[:3]):
                raise SQLFlowLimit('SQL list mutation at an aliased target is unresolved; analysis is incomplete')
            return
        name = target.value.id
        if (self._generator_scope[-1], name) in self._argument_list_reads:
            raise SQLFlowLimit('SQL list mutation during argument evaluation is unsupported; analysis is incomplete')
        if (self._generator_scope[-1], name) in self._iterated_lists and any(facts[:3]):
            raise SQLFlowLimit('SQL mutation during list iteration is unsupported; analysis is incomplete')
        before = self.value_facts(ast.Name(id=name, ctx=ast.Load()))
        opaque = False
        if isinstance(target.slice, ast.Slice):
            indices = [index for index in (target.slice.lower, target.slice.upper, target.slice.step)
                       if index is not None]
            # Slice assignment consumes an iterable. Unknown iterators can
            # invoke callbacks and mutate this list while they yield.
            if self.fact_kinds(facts)[0] not in {'list', 'tuple', 'range', 'str'}:
                if any(facts[:3]) or any(before[:3]):
                    raise SQLFlowLimit('SQL list mutation from an opaque slice iterable is unresolved; analysis is incomplete')
                opaque = True
            facts = self.element_facts(facts)
        else:
            indices = [target.slice]
        if any(self.value_kind(index)[0] != 'number' for index in indices):
            if any(facts[:3]) or any(before[:3]):
                raise SQLFlowLimit('SQL list mutation through an opaque index is unresolved; analysis is incomplete')
            opaque = True
        element = self.fact_kinds(before)[1]
        combined = self.with_kinds(self.join_value_facts(before, facts), 'list',
                                   self.join_element_shapes(element, self.element_shape(self.fact_kinds(facts))))
        self.bind_value_facts([name], combined)
        self.binding_sites[name] = sites
        # Like an opaque call, an unproved index/iterable may retain an
        # object. Even a write with no SQL facts must revoke that ownership;
        # a later SQL-bearing mutation cannot reuse the old private proof.
        if not opaque:
            self.exclusive_lists.add(name)

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
        previous = self._generator_replacement
        if all(isinstance(target, ast.Name) for target in node.targets):
            self._generator_replacement = (
                frozenset(target.id for target in node.targets), self.assigned_generators(node.value))
        try:
            self.visit(node.value)
        finally:
            self._generator_replacement = previous
        pending = [binding for target in node.targets
                   for binding in self.assignment_bindings(target, node.value)]
        if not self.numeric_alias_assignment(node.targets, node.value):
            self.escape_lists([node.value])
        for target, facts in pending:
            self.store_assignment(target, facts)
        if len(node.targets) == 1:
            self.exclusive_lists.update(self.fresh_list_targets(node.targets[0], node.value))
            self.grant_numeric_region(node.targets[0], node.value)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            if not self.numeric_alias_assignment([node.target], node.value):
                self.escape_lists([node.value])
        if node.value is not None:
            self.store_assignment(node.target, self.value_facts(node.value))
            self.exclusive_lists.update(self.fresh_list_targets(node.target, node.value))
            self.grant_numeric_region(node.target, node.value)
        else:
            self.visit(node.target)
        self.visit(node.annotation)

    def visit_Yield(self, node):
        if node.value is not None:
            self.visit(node.value)
            self.escape_lists([node.value])

    visit_YieldFrom = visit_Yield

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self.check_facade_store(node.target, self.value_facts(node.value))
        self.escape_lists([node.value])
        self.mark_assignment(binding_target_names(node.target), node.value)
        self._evaluated_values[node] = self.value_facts(node.value)

    def visit_Delete(self, node):
        for target in node.targets:
            self.visit(target)
            self.bind_value_facts(binding_target_names(target), (None, None, None, False, 'unknown'))

    def visit_AugAssign(self, node):
        self.visit(node.target)
        left = self.value_facts(node.target)
        if (isinstance(node.target, ast.Subscript) and isinstance(node.target.value, ast.Name)
                and node.target.value.id in self.exclusive_lists
                and self.numeric_reference(node.target.value) is None):
            # Closed numeric regions already captured the selected child's
            # shape above. This internal read is not an iterator exporting
            # child aliases, and generator RHS checks below still apply.
            left = self.iteration_facts(node.target.value)
        self.visit(node.value)
        self.note_possible_raise()
        self.check_facade_store(node.target, self.join_value_facts(left, self.value_facts(node.value)))
        if isinstance(node.target, ast.Name):
            if self.numeric_reference(node.target) is not None:
                raise SQLFlowLimit('SQL numeric list augmented mutation is unsupported; analysis is incomplete')
            list_update = isinstance(node.op, ast.Add) and self.fact_kinds(left)[0] == 'list'
            owned = node.target.id in self.exclusive_lists
            if list_update and self.generator_refs(self.value_facts(node.value)):
                raise SQLFlowLimit('SQL generator augmented assignment is unsupported; analysis is incomplete')
            if list_update and not owned and any(self.value_facts(node.value)[:3]):
                raise SQLFlowLimit('SQL list mutation aliasing is unsupported; analysis is incomplete')
            # += reads its left value before evaluating the RHS, unlike a
            # fresh lookup of the same name after an RHS assignment expression.
            self._evaluated_values[node.target] = left
            if list_update:
                # list += accepts any iterable; list + tuple would instead
                # raise. Keep the actual receiver shape and merge yielded
                # contents without inventing string interpolation.
                right = self.iteration_facts(node.value)
                element = self.fact_kinds(left)[1]
                facts = self.with_kinds(self.join_value_facts(left, right), 'list',
                                        self.join_element_shapes(element, self.element_shape(self.fact_kinds(right))))
                self.bind_value_facts([node.target.id], facts)
            else:
                value = ast.copy_location(ast.BinOp(left=node.target, op=node.op, right=node.value), node)
                self.mark_assignment([node.target.id], value)
            if list_update and owned and self.value_kind(node.value)[0] in {'list', 'tuple', 'range'}:
                # In-place builtin concatenation keeps the same exclusive
                # receiver. A rebind/escape while evaluating the RHS has
                # already revoked ownership before this check.
                self.exclusive_lists.add(node.target.id)
        elif isinstance(node.target, ast.Subscript):
            if (self.value_kind(node.target.value)[0] == 'list'
                    and self.generator_refs(self.value_facts(node.value))):
                raise SQLFlowLimit('SQL list mutation consumes a generator; analysis is incomplete')
            self._evaluated_values[node.target] = left
            value = ast.copy_location(ast.BinOp(left=node.target, op=node.op, right=node.value), node)
            self.store_list_item(node.target, self.value_facts(value))

    def sql_keyword_arguments(self, node):
        """Bind exact keyword dictionaries without treating bound data as SQL.

        Dictionary entries overwrite earlier entries, but separate keyword
        expansions may not duplicate a name. An opaque mapping can overwrite
        any earlier dictionary entry; later literal entries remain exact.
        """
        cache = self._ownership_syntax.setdefault('sql_keyword_arguments', {})
        if node in cache:
            return cache[node]

        def mapping(value, depth=0):
            if not isinstance(value, ast.Dict):
                return {}, True, False
            if depth >= 64:
                raise SQLFlowLimit('SQL keyword expansion nesting exceeded; analysis is incomplete')
            values, unknown, invalid = {}, False, False
            for key, item in zip(value.keys, value.values):
                self.step()
                if key is None:
                    incoming, opaque, malformed = mapping(item, depth + 1)
                    if opaque:
                        values.clear()
                    values.update(incoming)
                    unknown |= opaque
                    invalid |= malformed
                elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                    values[key.value] = item
                elif isinstance(key, ast.Constant):
                    invalid = True
                else:
                    values.clear()
                    unknown = True
            return values, unknown, invalid

        values, unknown, invalid = {}, False, False
        for keyword in node.keywords:
            self.step()
            if keyword.arg is None:
                incoming, opaque, malformed = mapping(keyword.value)
                unknown |= opaque
                invalid |= malformed or bool(values.keys() & incoming.keys())
                values.update(incoming)
            else:
                invalid |= keyword.arg in values
                values[keyword.arg] = keyword.value
        result = values, unknown, invalid
        cache[node] = result
        return result

    def unresolved_sql_argument_slots(self, node, short):
        keywords, unknown, invalid = self.sql_keyword_arguments(node)
        if invalid:
            return False
        if short in EXECUTE_METHODS:
            if ((node.args and not isinstance(node.args[0], ast.Starred))
                    or SQL_ARGUMENT_KEYWORDS.get(short, frozenset()) & keywords.keys()):
                return False
            # The ordinary sink flow already classifies *args as an aggregate
            # value. An opaque **mapping can still supply an unmodeled SQL slot.
            return unknown
        if short == 'extra':
            return any(name not in keywords
                       and not (len(node.args) > index and not any(
                           isinstance(argument, ast.Starred) for argument in node.args[:index + 1]))
                       and (unknown or any(isinstance(argument, ast.Starred) for argument in node.args))
                       for index, name in enumerate(('select', 'where')))
        return False

    def sql_argument(self, node, short=None):
        if short is None:
            short = sql_sink_name(node, self.ownership_bindings())
        if not short:
            return None
        keywords, _, invalid = self.sql_keyword_arguments(node)
        if invalid:
            return None
        if short in EXECUTE_METHODS:
            if node.args and not isinstance(node.args[0], ast.Starred):
                return node.args[0]
            for name, value in keywords.items():
                if name in SQL_ARGUMENT_KEYWORDS.get(short, frozenset()):
                    return value
            if node.args:
                return node.args[0]
        if short == 'extra':
            return keywords.get('where')
        return None

    def sql_arguments(self, node, short=None):
        """Yield SQL expressions and their statement/fragment/mapping context.

        Django extra(select, where, params, ...) accepts SQL fragments, not
        complete statements. Its select dictionary keys are result aliases;
        only the values are raw SQL. Do not inspect params/select_params.
        """
        if short is None:
            short = sql_sink_name(node, self.ownership_bindings())
        if short != 'extra':
            argument = self.sql_argument(node, short)
            if argument is not None:
                yield argument, 'statement'
            return
        keywords, _, invalid = self.sql_keyword_arguments(node)
        if invalid:
            return
        for index, name in enumerate(('select', 'where')):
            argument = keywords.get(name)
            if argument is None and len(node.args) > index:
                # An unknown *args expansion makes subsequent positions
                # ambiguous. Explicit keywords above remain identifiable.
                if not any(isinstance(arg, ast.Starred) for arg in node.args[:index + 1]):
                    argument = node.args[index]
            if argument is None:
                continue
            yield argument, 'select' if name == 'select' else 'fragment'

    def literal_statement_scopes(self):
        """Identify literal SQL owners whose unrelated bodies can be omitted.

        Inspect the complete lexical call inventory, including deferred bodies
        and definition-time expressions. Keep ambiguous execution aliases,
        opaque SQL facades, fragments, argument expansions and every computed
        SQL value on the ordinary flow path. The owners still need full flow
        analysis, including callback refusals. This is not a larger budget.
        """
        bindings = self.ownership_bindings()
        if bindings.sql_facade_flow()[1] or bindings.escaped_sql_methods():
            return None
        found = False
        scopes = set()
        for call in bindings.calls:
            self.step()
            if bindings.unresolved_sql_aliases(call):
                return None
            short = sql_sink_name(call, bindings)
            if not short:
                continue
            if (short == 'extra' or any(isinstance(arg, ast.Starred) for arg in call.args)
                    or any(keyword.arg is None for keyword in call.keywords)):
                return None
            keyword_slots = sum(keyword.arg in SQL_ARGUMENT_KEYWORDS.get(short, ())
                                for keyword in call.keywords)
            if keyword_slots + bool(call.args) != 1:
                return None
            arguments = list(self.sql_arguments(call, short))
            if (not arguments or any(context != 'statement'
                    or not isinstance(argument, ast.Constant) or not isinstance(argument.value, str)
                    for argument, context in arguments)):
                return None
            found = True
            scope = bindings.scope_of[call]
            while scope is not None:
                self.step()
                scopes.add(scope['node'])
                scope = scope['parent']
        if not found:
            return None
        # Retain referenced helpers and callbacks, including aliases and
        # literal getattr names. Over-approximate equal spellings rather than
        # treating an unresolved receiver as proof that a body is unrelated.
        named, children = {}, {}
        for owner, scope in bindings.owner_scopes.items():
            self.step()
            if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                named.setdefault(owner.name, set()).add(owner)
            if scope['parent'] is not None:
                children.setdefault(scope['parent']['node'], []).append(owner)
        pending, retained = list(scopes), set()
        while pending:
            owner = pending.pop()
            if owner in retained:
                continue
            self.step()
            retained.add(owner)
            references = bindings.owner_scopes[owner]['references']
            if bindings.owner_scopes[owner]['reflective']:
                # Dynamic lookup in a retained scope needs the existing full
                # visitor; no callable-name closure can be proved here.
                return None
            for name in references:
                self.step()
                pending.extend(named.get(name, ()))
            for child in children.get(owner, ()):
                if (isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
                        or not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
                        or getattr(child, 'decorator_list', ())
                        or getattr(child, 'name', '').startswith('__')):
                    pending.append(child)
        return frozenset(retained)

    def visit_Call(self, node):
        self._facade_results.discard(node)
        self._completed_predicates.discard(node)
        known_builtin = (isinstance(node.func, ast.Name) and self.builtin_is_unshadowed(node.func.id)
                         and node.func.id in {'list', 'tuple', 'set', 'frozenset', 'sorted', 'min', 'max', 'sum',
                                              'any', 'all', 'iter', 'str', 'repr', 'bool', 'id', 'type'})
        if not known_builtin:
            self.note_possible_raise()
        borrowed = self.immediate_generator_borrow(node)
        enclosing_iterations = self._iterated_lists
        # The sink's own first line is what a guard has to precede (GH #133).
        # Using the sink line rather than the interpolated value's line keeps
        # a guard written inside the same multi-line call from counting.
        uncertain_aliases = self.ownership_bindings().unresolved_sql_aliases(node)
        is_sink = bool(list(self.sql_arguments(node))) or bool(uncertain_aliases)
        previous_sink = self.sink_lineno
        if is_sink:
            self.sink_lineno = node.lineno
        argument_epochs = {}
        enclosing_list_reads = self._argument_list_reads
        self._argument_list_reads = enclosing_list_reads.copy()
        try:
            self.visit(node.func)
            # Python loads the callable before evaluating any argument. A
            # walrus/argument callback can rebind its name, but cannot change
            # the already captured function object for this invocation.
            if isinstance(node.func, ast.Name):
                self._evaluated_call_targets[node] = self.ownership_call_target(node)
            if isinstance(node.func, ast.Name) and self._generator_scope:
                target = self.ownership_call_target(node)
                if target and target[0] == 'function':
                    owner = self.ownership_bindings().owner_scopes[target[1]]['parent']
                    if (owner is not None and owner['node'] is self._generator_scope[-1]
                            and target[1] not in self.binding_sites.get(target[1], frozenset())):
                        # A definitely absent local callable fails before its
                        # arguments execute. A joined maybe-defined site keeps
                        # its normal argument path and later proof refusal.
                        raise SQLFlowLimit('SQL local helper definition order is unresolved; analysis is incomplete')
            for argument in node.args:
                self.visit(argument)
                argument_epochs[argument] = self.validation_epoch(argument)
                self.remember_list_argument(argument)
            for keyword in node.keywords:
                self.visit(keyword.value)
                argument_epochs[keyword.value] = self.validation_epoch(keyword.value)
                self.remember_list_argument(keyword.value)
            joined = self.string_join_facts(node)
            if (isinstance(node.func, ast.Name) and node.func.id == 'getattr'
                    and self.builtin_is_unshadowed('getattr') and len(node.args) >= 2
                    and self.value_kind(node.args[0])[0] == 'list'
                    and (not isinstance(node.args[1], ast.Constant)
                         or not isinstance(node.args[1].value, str) or node.args[1].value in LIST_MUTATORS)):
                raise SQLFlowLimit('SQL list mutation capability is reflected; analysis is incomplete')
            if (isinstance(node.func, ast.Attribute) and node.func.attr in LIST_MUTATORS
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'list'
                    and self.builtin_is_unshadowed('list') and node.args
                    and self.value_kind(node.args[0])[0] == 'list'):
                raise SQLFlowLimit('SQL list mutation through an unbound method is unsupported; analysis is incomplete')
            if call_name(node.func).rsplit('.', 1)[-1] in {
                    'locals', 'globals', 'vars', 'eval', 'exec', 'currentframe', '_getframe'}:
                self.exclusive_lists.clear()
                for identity in tuple(self.numeric_regions):
                    self.retire_numeric_region(identity)
            copying_builtin = (isinstance(node.func, ast.Name)
                               and self.builtin_is_unshadowed(node.func.id)
                               and node.func.id in {'list', 'tuple', 'sorted', 'len', 'bool', 'str', 'repr', 'id', 'type'})
            numeric_readonly = (copying_builtin and node.func.id in {'len', 'bool', 'str', 'repr', 'id', 'type'})
            if not numeric_readonly and self.numeric_regions:
                # Non-retention is weaker than non-mutation. A helper may
                # rewrite a borrowed child without retaining it; copying a
                # parent list can also export those mutable child aliases.
                self.retire_numeric_arguments([*node.args, *(keyword.value for keyword in node.keywords)])
            list_plan = self.local_list_effect_plan(node, argument_epochs, enclosing_list_reads)
            if not copying_builtin:
                nonretaining = self.nonretaining_call_arguments(node)
                if list_plan is not None:
                    nonretaining.update(list_plan[2].values())
                if joined is not None:
                    nonretaining.add(node.args[0])
                if nonretaining and self._pending_raise is not None:
                    # A raised exception can retain a helper frame and its
                    # arguments. The proof applies only to normal completion.
                    exceptional = list(self._pending_raise)
                    names = {argument.id for argument in nonretaining if isinstance(argument, ast.Name)}
                    exceptional[10] = exceptional[10] - names
                    self._pending_raise = tuple(exceptional)
                self.escape_lists([argument for argument in
                                   [*node.args, *(keyword.value for keyword in node.keywords)]
                                   if argument not in nonretaining])
                if (node in self._consuming_iterables and isinstance(node.func, ast.Name)
                        and node.func.id in {'iter', 'reversed'} and nonretaining):
                    facts = self.value_facts(node.args[0])
                    self._evaluated_values[node] = self.with_kinds(facts, 'iterator', self.fact_kinds(facts)[1])
            # A direct builtin consumer owns its unaliased generator until
            # this call returns. The input root is never yielded or exported.
            # Short-circuit predicates additionally prohibit body calls;
            # full consumers interpret effects with the iteration guard.
            # Exceptional stores still lose ownership at iterator creation.
            self.exclusive_lists.update(borrowed)
            if borrowed:
                self._iterated_lists = self._iterated_lists | {
                    (self._generator_scope[-1], name) for name in borrowed}
            if list_plan is None and isinstance(node.func, ast.Name):
                target = self.ownership_call_target(node)
                if (target and target[0] == 'function' and target[1] not in self._sealed_closures
                        and self._generator_scope
                        and self.ownership_bindings().owner_scopes[target[1]]['parent']['node']
                            is self._generator_scope[-1]
                        and (self.string_result(node)
                             or self.declared_closure_cells(target[1])
                             and self.has_collection_key_callbacks()
                             and self.collection_key_effects_unmodeled()
                             or self._short_circuiting
                             and target[1] in self.ownership_bindings().local_sql_effects())):
                    # A return-shape proof alone is not a text-provenance
                    # proof. Interpret a stable local string or SQL helper
                    # with its actual inputs, even with no enclosing list.
                    # A nonlocal receiver/callable write can also introduce a
                    # set.update path; the cell model must interpret or refuse
                    # that alias instead of discarding its deferred effects.
                    # SQL effects inside a predicate need the same guarded
                    # closure transfer as explicit calls to cursor.execute.
                    self.sealed_list_captures(target[1], allow_empty=True)
            self.check_set_update_keys(node)
            handled = (list_plan is not None and self.local_list_effect_call(node, list_plan)
                       or self.sealed_closure_call(node) or self.generator_call(node) or joined is not None)
            if (self._short_circuiting and not handled and not is_sink
                    and not self.generator_database_fetch(node)
                    and not self.primitive_facade_call(node)
                    and not (self.intrinsic_range_call(node)
                             and all(self.value_kind(argument)[0] == 'number' for argument in node.args))
                    and not is_sanitizer_call(node, self.sanitizers, self.bindings)):
                # An opaque callback can mutate a captured dictionary/object
                # or a mutable argument between yields. Neither a pure-looking
                # return value nor the lack of a walrus proves its effects.
                raise SQLFlowLimit('SQL generator call effects are unresolved; analysis is incomplete')
            if not handled:
                self.check_collection_constructor(node)
                # This is return provenance, not an effect certificate. Keep
                # ordinary escape, callback and consumer-effect refusals.
                self.facade_builder_result(node)
            if (self._consumer_calls or self._closure_worklist) and not handled and not is_sink and not copying_builtin and not known_builtin:
                receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
                intrinsic_view = (receiver is not None and self.value_kind(receiver)[0] == 'dict'
                                  and node.func.attr in {'values', 'items', 'keys'}
                                  and not node.args and not node.keywords)
                intrinsic_check = self.intrinsic_range_call(node) or (isinstance(node.func, ast.Name) and node.func.id == 'isinstance'
                                   and self.builtin_is_unshadowed('isinstance') and len(node.args) == 2
                                   and not node.keywords and isinstance(node.args[1], ast.Name)
                                   and node.args[1].id in {'str', 'int', 'float', 'bool', 'list', 'tuple', 'dict', 'set', 'frozenset'}
                                   and self.builtin_is_unshadowed(node.args[1].id))
                if intrinsic_check:
                    self._evaluated_values[node] = (None, None, None, False, 'static')
                if (not intrinsic_view and not intrinsic_check and not is_sanitizer_call(node, self.sanitizers, self.bindings)
                        and (self._list_effect_active or any(any(self.value_facts(value)[:3]) for value in
                                [*node.args, *(keyword.value for keyword in node.keywords),
                                 *([receiver] if receiver is not None else [])]))):
                    raise SQLFlowLimit('SQL consumer call effects are unresolved; analysis is incomplete')
            if (not handled and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {'append', 'extend', 'insert', '__setitem__', '__iadd__', '__init__'}
                    and self.value_kind(node.func.value)[0] == 'list'
                    and any(any(self.value_facts(argument)[:3])
                            or self._generator_running and self.value_facts(argument)[4] != 'static'
                            and self.fact_kinds(self.value_facts(argument))[0] != 'number'
                            for argument in node.args)):
                raise SQLFlowLimit('SQL list mutation aliasing is unsupported; analysis is incomplete')
            if isinstance(node.func, ast.Attribute) and not handled:
                self.escape_lists([node.func.value])
            if (not handled and isinstance(node.func, ast.Name) and node.func.id == 'list'
                    and self.builtin_is_unshadowed('list') and len(node.args) <= 1 and not node.keywords
                    and not any(isinstance(argument, ast.Starred) for argument in node.args)):
                facts = self.value_facts(node.args[0]) if node.args else (None, None, None, False, 'static')
                self._evaluated_values[node] = self.with_kinds(facts, 'list', self.fact_kinds(facts)[1])
            if 'constructor' in self.set_update_capabilities(self.value_kind(node.func)[0]):
                facts = self.value_facts(node)
                if self.fact_kinds(facts)[0] != 'set':
                    native = (self.ownership_call_target(node) in {
                                  ('unbound', 'set'), ('import', 'builtins.set')}
                              and len(node.args) <= 1 and not node.keywords
                              and not any(isinstance(argument, ast.Starred) for argument in node.args)
                              and self.closed_generator_builtin_binding('set'))
                    # Construction proves a receiver, never mutable element
                    # shapes. Mixed callable joins retain refusal capability
                    # only, without claiming that a native call took place.
                    self._evaluated_values[node] = self.with_kinds(
                        facts, 'set' if native else frozenset({'receiver'}))
            if self.intrinsic_range_call(node):
                # range either raises or yields integers; its bounds are not
                # SQL values. Their eager side effects have already run.
                self._evaluated_values[node] = self.with_kinds(
                    (None, None, None, False, 'tainted'), 'range', 'number')
            if (isinstance(node.func, ast.Name) and node.func.id == 'len'
                    and self.builtin_is_unshadowed('len') and len(node.args) == 1
                    and not isinstance(node.args[0], ast.Starred) and not node.keywords
                    and not self.ownership_bindings().dynamic_namespace
                    and not self.ownership_bindings().builtin_namespace
                    and 'len' not in self.ownership_bindings().member_writes):
                # len validates __len__'s return and produces an exact int.
                # Only the successful result's shape is proved: argument
                # evaluation, call effects and SQL provenance remain intact.
                self._evaluated_values[node] = self.with_kinds(self.value_facts(node), 'number')
            if not handled and self.string_result(node):
                # A return shape says nothing about SQL provenance or purity.
                # Keep every argument's captured SQL facts and all call effects;
                # only subsequent iteration of an exact string is intrinsic.
                self._evaluated_values[node] = self.with_kinds(self.value_facts(node), 'str', 'str')
            regex_shape = self.regex_result_shape(node)
            if regex_shape is not None:
                self._evaluated_values[node] = self.with_kinds(self.value_facts(node), *regex_shape)
            if joined is not None:
                # An exact string separator joining builtin string elements
                # returns their text, not a new external-data source. Opaque
                # iterables keep the normal call facts and effect boundaries.
                risk = None if joined[4] == 'static' else 'critical' if joined[4] == 'tainted' else 'warning'
                self._evaluated_values[node] = self.with_kinds((
                    join_sql_risks(joined[0], risk if joined[3] else None),
                    join_sql_risks(joined[1], risk), join_sql_risks(joined[2], risk),
                    joined[3], joined[4]), 'str', 'str')
            # All effects have now occurred, but each argument retains its
            # own evaluation-time value. Markers suppress the emitted rule in
            # find(), never execution.
            if is_sink:
                self.classify_sink(node)
            sql_method = sql_sink_name(node, self.ownership_bindings())
            if sql_method and self.unresolved_sql_argument_slots(node, sql_method):
                raise SQLFlowLimit('SQL execution argument slots are unresolved; analysis is incomplete')
            if uncertain_aliases:
                bindings = self.ownership_bindings()
                if ({'__code__', '__globals__', '__defaults__', '__kwdefaults__'} & bindings.member_writes
                        and bindings.possible_sql_methods(node.func)):
                    # A saved bound method retains the function object, not
                    # an immutable copy of its code/defaults. A replacement
                    # can execute hidden default values even when every
                    # explicit argument is a literal SQL statement.
                    raise SQLFlowLimit('SQL saved callable metadata is unresolved; analysis is incomplete')
                replacement = self.ownership_bindings().plain_alias_replacement(node)
                safe = replacement is not None and replacement[1] is None
                if replacement is not None and replacement[1] is not None:
                    argument = _bind_call_arguments(node, {'positional': _positional_parameters(replacement[0])}).get(
                        replacement[1])
                    safe = (argument is not None and not any(isinstance(value, ast.Starred) for value in node.args)
                            and all(keyword.arg is not None for keyword in node.keywords)
                            and self.value_kind(argument)[0] in {'str', 'list', 'tuple', 'set', 'dict', 'range', 'number', 'none'})
                if not safe and any(
                        self.sql_risk(argument, require_sql='extra' not in uncertain_aliases) is not None
                        for argument in [*node.args, *(keyword.value for keyword in node.keywords)]):
                    # An unknown replacement has no verified query/params
                    # contract. It may execute a value from any argument,
                    # including one that the imported API would have bound.
                    raise SQLFlowLimit('SQL aliased execution binding is unresolved; analysis is incomplete')
            if (node in self.ownership_bindings().sql_facade_flow()[1] and not handled
                    and not is_sanitizer_call(node, self.sanitizers, self.bindings)
                    and not self.primitive_facade_call(node)):
                values = [*node.args, *(keyword.value for keyword in node.keywords)]
                if isinstance(node.func, ast.Attribute):
                    values.append(node.func.value)
                if any(self.sql_risk(value) is not None or self.unresolved_facade_return(value)
                       for value in values):
                    raise SQLFlowLimit('SQL facade forwarding call is unresolved; analysis is incomplete')
        finally:
            self.sink_lineno = previous_sink
            self._iterated_lists = enclosing_iterations
            self._argument_list_reads = enclosing_list_reads
        stable = {argument for argument, epoch in argument_epochs.items()
                  if epoch is not None and epoch == self.validation_epoch(argument)}
        if not is_sanitizer_call(node, self.sanitizers, self.bindings):
            self.invalidate_attribute_validations()
        if node not in self._completed_predicates:
            self.note_possible_raise()
        # Only successful completion establishes a proof. The pending error
        # store above must remain unvalidated when a handler catches failure.
        self.validated.update(call_validated_segments(
            node, self.text, self.sanitizers, self.sanitizer_summaries, stable, self.bindings))

    def unresolved_facade_return(self, value):
        """Refuse opaque consumption of an unmodeled SQL-producing result.

        This is a may-dependency check, not a return-value or purity proof.
        Follow returned expressions and their assignments, including loop
        bindings, so richer helper bodies cannot silently drop constructed
        SQL. Fixed returned text and discarded SQL-building work do not
        create this boundary; successful value projections remain decisive.
        """
        bindings = self.ownership_bindings()
        cache = self._ownership_syntax.setdefault('facade_return_queries', {})
        # Only completed return projections affect this otherwise immutable
        # lexical query. Include their identities so a static projection in
        # one evaluation cannot suppress an unresolved result in another.
        cache_key = value, frozenset(self._facade_results)
        if cache_key in cache:
            return cache[cache_key]
        if 'facade_value_dependencies' not in self._ownership_syntax:
            assignments, returns, augmented = {}, {}, set()
            # One charged pass over the existing lexical index. Rewalking
            # every callee body at each opaque use exhausts the ordinary
            # budget in interpreters with many local helper calls.
            for statement, scope in bindings.scope_of.items():
                self.step()
                if isinstance(statement, ast.Return) and statement.value is not None:
                    returns.setdefault(scope['node'], []).append(statement.value)
                if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    if statement.value is None:
                        continue
                    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                    expression = statement.value
                elif isinstance(statement, (ast.For, ast.AsyncFor)):
                    targets, expression = [statement.target], statement.iter
                else:
                    continue
                for target in targets:
                    owner = bindings.scope_of.get(target, scope)['node']
                    for name in binding_target_names(target):
                        key = owner, name
                        assignments.setdefault(key, []).append(expression)
                        if isinstance(statement, ast.AugAssign) and isinstance(statement.op, (ast.Add, ast.Mod)):
                            augmented.add(key)
            dynamic_updates = {key for key in augmented if
                               any(not all_static_strings(expression) for expression in assignments[key])
                               or hasattr(key[0], 'args') and key[1] in _all_parameters(key[0])}
            self._ownership_syntax['facade_value_dependencies'] = assignments, returns, dynamic_updates
        assignments, returns, dynamic_updates = self._ownership_syntax['facade_value_dependencies']
        static = self._ownership_syntax.setdefault('facade_return_states', {})
        targets = self._ownership_syntax.setdefault('facade_return_targets', {})
        root = value, False, False

        def solve(blocked, memo):
            if root in memo:
                return memo[root]
            pending, edges, reverse, positive = [root], {}, {}, set()
            while pending:
                identity = pending.pop()
                if identity in memo:
                    if memo[identity]:
                        positive.add(identity)
                    continue
                if identity in edges or static.get(identity) is False:
                    continue
                self.step()
                node, dynamic, returned = identity
                dependencies = []
                edges[identity] = dependencies
                if isinstance(node, ast.Constant):
                    if returned and dynamic and isinstance(node.value, str) and SQL_RE.search(node.value):
                        positive.add(identity)
                    continue
                if isinstance(node, ast.Name):
                    owner = bindings.lexical_owner(node)
                    if owner is not None:
                        key = owner['node'], node.id
                        dynamic = dynamic or key in dynamic_updates
                        dependencies.extend((expression, dynamic, returned) for expression in assignments.get(key, ()))
                else:
                    if isinstance(node, ast.Call):
                        if node in blocked or is_sanitizer_call(node, self.sanitizers, self.bindings):
                            continue
                        if node not in targets:
                            targets[node] = bindings.resolve(node.func)
                        target = targets[node]
                        if (target and target[0] == 'unbound' and target[1] in {'len', 'id', 'type', 'bool'}
                                and not bindings.dynamic_namespace and not bindings.builtin_namespace):
                            continue  # these returned values are not SQL text
                        if target and target[0] == 'function':
                            dependencies.extend((expression, False, True) for expression in returns.get(target[1], ()))
                        if isinstance(node.func, ast.Attribute) and node.func.attr in {'format', 'format_map'}:
                            dynamic = dynamic or any(not isinstance(argument, ast.Constant) for argument in
                                                     [*node.args, *(keyword.value for keyword in node.keywords)])
                    elif isinstance(node, ast.JoinedStr):
                        dynamic = dynamic or any(isinstance(part, ast.FormattedValue)
                                                 and not isinstance(part.value, ast.Constant) for part in node.values)
                    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
                        dynamic = dynamic or not all_static_strings(node)
                    if isinstance(node, ast.IfExp):
                        children = (node.body, node.orelse)
                    elif isinstance(node, ast.Subscript):
                        children = (node.value,)
                    elif isinstance(node, ast.Dict):
                        children = node.values
                    else:
                        children = ast.iter_child_nodes(node)
                    dependencies.extend((child, dynamic, returned) for child in children)
                for child in dependencies:
                    reverse.setdefault(child, set()).add(identity)
                    pending.append(child)
            pending = list(positive)
            while pending:
                for parent in reverse.get(pending.pop(), ()):
                    self.step()
                    if parent not in positive:
                        positive.add(parent)
                        pending.append(parent)
            # A cycle is negative only after its entire reachable component
            # closes. Never memoize an unfinished recursive projection.
            memo.update((identity, identity in positive) for identity in edges)
            return root in positive

        result = solve(frozenset(), static)
        if result and self._facade_results:
            contexts = self._ownership_syntax.setdefault('facade_return_contexts', {})
            blocked = frozenset(self._facade_results)
            result = solve(blocked, contexts.setdefault(blocked, {}))
        cache[cache_key] = result
        return result

    def facade_builder_result(self, call):
        """Transfer a closed local builder's actual returned SQL.

        A string-shape summary cannot carry SQL constructed inside a helper.
        Evaluate these bounded bodies in their lexical frame, using captured
        argument values and only visible lexical cells. Never substitute a
        caller's same-spelled local for an unrelated module or sibling cell.
        Effects and protocol calls still pass through the normal visitor.
        """
        if not isinstance(call.func, ast.Name):
            # The closed-local-callable proof below excludes class members;
            # an attribute dispatch has no eligible builder frame here.
            return False
        bindings = self.ownership_bindings()
        functions, _ = bindings.sql_facade_flow()
        if not functions or bindings.function_owner(call) not in functions:
            return False
        target = self.ownership_call_target(call)
        if not target or target[0] != 'function' or target[2] or target[1] not in functions:
            return False
        function = target[1]
        if (not isinstance(function, ast.FunctionDef) or function.decorator_list
                or function.args.vararg or function.args.kwarg
                or bindings.dynamic_namespace or bindings.builtin_namespace
                or {'__code__', '__globals__'} & bindings.member_writes
                or not bindings.closed_local_callable(function)):
            return False
        body = [statement for statement in function.body if not (
            isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str))]
        if not body:
            return False
        pending, has_return = list(body), False
        while pending:
            self.step()
            statement = pending.pop()
            if isinstance(statement, ast.Return):
                has_return = True
            elif isinstance(statement, ast.If):
                pending.extend(statement.body)
                pending.extend(statement.orelse)
            elif isinstance(statement, ast.Pass):
                continue
            elif (not isinstance(statement, (ast.Assign, ast.AnnAssign))
                  or statement.value is None
                  or not all(isinstance(value, ast.Name) for value in
                             (statement.targets if isinstance(statement, ast.Assign) else [statement.target]))):
                if self.facade_string_return(function):
                    # Exact string shape permits ordinary len/string uses,
                    # but carries no SQL provenance or effect certificate.
                    self._evaluated_values[call] = self.with_kinds(self.value_facts(call), 'str', 'str')
                return False
        if not has_return:
            return False
        nodes = [node for statement in body for node in ast.walk(statement)]
        if any(isinstance(node, (ast.Lambda, ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp,
                                 ast.Yield, ast.YieldFrom, ast.Await, ast.NamedExpr)) for node in nodes):
            return False
        if function in self._facade_calls:
            raise SQLFlowLimit('SQL facade return recursion is unresolved; analysis is incomplete')
        if (any(isinstance(argument, ast.Starred) for argument in call.args)
                or any(keyword.arg is None for keyword in call.keywords)
                or any(not isinstance(default, ast.Constant) for default in function.args.defaults)
                or any(default is not None and not isinstance(default, ast.Constant)
                       for default in function.args.kw_defaults)):
            return False
        positional = _positional_parameters(function)
        actual = _bind_call_arguments(call, {'positional': positional})
        for name, default in zip(positional[len(positional) - len(function.args.defaults):], function.args.defaults):
            actual.setdefault(name, default)
        for argument, default in zip(function.args.kwonlyargs, function.args.kw_defaults):
            if default is not None:
                actual.setdefault(argument.arg, default)
        if set(actual) != _all_parameters(function):
            return False
        facts = {name: self.value_facts(value) for name, value in actual.items()}
        if any(self.generator_refs(value) for value in facts.values()):
            return False
        local = set(bindings.owner_scopes[function]['names'])
        free = {node.id: node for node in nodes if isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load) and node.id not in local}
        for name, reference in free.items():
            owner = bindings.lexical_owner(reference)
            visible = owner is not None and owner['node'] in self._generator_scope
            if visible:
                boundary = self._generator_scope.index(owner['node']) + 1
                visible = not any(name in bindings.owner_scopes[scope]['names']
                                  for scope in self._generator_scope[boundary:])
            if visible:
                facts[name] = self.value_facts(ast.Name(id=name, ctx=ast.Load()))
            else:
                # A stable literal remains available even when a caller
                # shadows it. Mutable/unresolved free values have no proof.
                assignment = bindings.literal_assignments.get((owner['node'], name)) if owner else None
                literal = assignment.value if assignment is not None else None
                if (owner is not None and len(owner['names'].get(name, ())) == 1
                        and isinstance(literal, ast.Constant)):
                    facts[name] = self.value_facts(literal)
                else:
                    facts[name] = (None, None, None, False, 'unknown')
            if self.generator_refs(facts[name]):
                return False
        probe = self.flow_probe()
        state = list(probe.sql_state())
        for index in (0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14):
            state[index].clear()
        probe.restore_sql_state(tuple(state))
        probe._evaluated_values.clear()
        lexical, scope = [], bindings.owner_scopes[function]
        while scope is not None:
            lexical.append(scope['node'])
            scope = scope['parent']
        probe._generator_scope = tuple(reversed(lexical))
        probe.func_stack = [node for node in probe._generator_scope if isinstance(node, ast.FunctionDef)]
        probe._comprehension_locals.clear()
        probe._facade_calls = self._facade_calls | {function}
        probe._facade_return_complete = True
        probe._return_slot = '\0sql_return'
        for name, value in facts.items():
            probe.bind_value_facts([name], value)
        try:
            flow = probe.statements(body, probe.sql_state())
        finally:
            for identity, finding in probe._sink_risks.items():
                previous = self._sink_risks.get(identity)
                if previous is None or finding[0] == 'critical':
                    self._sink_risks[identity] = finding
        returned = []
        if flow.get('return') is not None:
            probe.restore_sql_state(flow['return'])
            returned.append(probe.value_facts(ast.Name(id=probe._return_slot, ctx=ast.Load())))
        if flow.get('normal') is not None:
            returned.append(self.with_kinds((None, None, None, False, 'static'), 'none'))
        if not returned:
            raise SQLFlowLimit('SQL facade return completion is unresolved; analysis is incomplete')
        if any(self.generator_refs(value) for value in returned):
            raise SQLFlowLimit('SQL facade return cursor is unresolved; analysis is incomplete')
        self._evaluated_values[call] = self.join_value_facts(*returned)
        if probe._facade_return_complete:
            self._facade_results.add(call)
        return True

    def facade_string_return(self, function):
        """Exact local string writes can establish shape without text flow.

        This is only called after the closed callable/namespace checks. A
        loop can prevent bounded return projection while all its successful
        returns still have builtin string type. Unknown assignments, class
        instances, parameters and indirect cell writes retain no proof.
        """
        cache = self._ownership_syntax.setdefault('facade_string_returns', {})
        if function in cache:
            return cache[function]
        bindings = self.ownership_bindings()
        writes, returns, pending = {}, [], list(function.body)
        while pending:
            self.step()
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await)):
                cache[function] = False
                return False
            if isinstance(node, ast.Return):
                returns.append(node.value)
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                parent = bindings.parents.get(node)
                value = parent.value if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) else None
                writes.setdefault(node.id, []).append(value)
            pending.extend(ast.iter_child_nodes(node))

        def exact_string(node, seen=frozenset()):
            self.step()
            if isinstance(node, ast.Constant):
                return isinstance(node.value, str)
            if isinstance(node, ast.JoinedStr):
                return len(node.values) > 1 or bool(node.values and isinstance(node.values[0], ast.Constant))
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                return exact_string(node.left, seen) and exact_string(node.right, seen)
            if isinstance(node, ast.IfExp):
                return exact_string(node.body, seen) and exact_string(node.orelse, seen)
            if (not isinstance(node, ast.Name) or node.id in seen
                    or node.id in bindings.indirect_rebindings
                    or node.id in _all_parameters(function)):
                return False
            owner = bindings.lexical_owner(node)
            values = writes.get(node.id, ())
            return (owner is not None and owner['node'] is function and bool(values)
                    and len(values) == len(owner['names'].get(node.id, ()))
                    and all(exact_string(value, seen | {node.id}) for value in values))

        # Falling off the body returns None; require an explicit final return
        # rather than treating an arbitrary loop/branch as total execution.
        result = bool(function.body and isinstance(function.body[-1], ast.Return)
                      and returns and all(exact_string(value) for value in returns))
        cache[function] = result
        return result

    def primitive_facade_call(self, call):
        """Prove a few ordinary operations on exact builtin values."""
        bindings = self.ownership_bindings()
        if bindings.dynamic_namespace or bindings.builtin_namespace:
            return False
        target = bindings.resolve(call.func)
        if (any(isinstance(argument, ast.Starred) for argument in call.args)
                or any(keyword.arg is None for keyword in call.keywords)):
            return False
        primitive = {'str', 'number', 'none'}
        if target == ('unbound', 'print'):
            if bindings.reflective_member_writes or {'stdout', 'write', 'flush'} & bindings.member_writes:
                return False
            for keyword in call.keywords:
                if keyword.arg == 'file':
                    if not isinstance(keyword.value, ast.Constant) or keyword.value.value is not None:
                        return False
                elif keyword.arg not in {'sep', 'end', 'flush'} or self.value_kind(keyword.value)[0] not in primitive:
                    return False
            return all(self.value_kind(argument)[0] in primitive for argument in call.args)
        if target == ('unbound', 'len'):
            return (len(call.args) == 1 and not call.keywords
                    and self.value_kind(call.args[0])[0] in primitive | {'list', 'tuple', 'set', 'dict', 'range'})
        if target and target[0] == 'unbound' and target[1] in {'str', 'repr', 'ascii', 'bool', 'int', 'float', 'id', 'type'}:
            return not call.keywords and all(self.value_kind(argument)[0] in primitive for argument in call.args)
        if (isinstance(call.func, ast.Attribute) and self.value_kind(call.func.value)[0] == 'str'
                and callable(getattr(str, call.func.attr, None))):
            if call.func.attr == 'encode':
                arguments = {'encoding': 'utf-8', 'errors': 'strict'}
                if len(call.args) > 2 or any(keyword.arg not in arguments for keyword in call.keywords):
                    return False
                supplied = dict(zip(('encoding', 'errors'), call.args))
                supplied.update((keyword.arg, keyword.value) for keyword in call.keywords)
                if any(not isinstance(value, ast.Constant) or not isinstance(value.value, str)
                       for value in supplied.values()):
                    return False
                arguments.update((name, value.value) for name, value in supplied.items())
                if arguments['encoding'].lower().replace('_', '-') not in {'utf-8', 'utf8', 'ascii', 'latin-1', 'latin1'}:
                    return False
                if arguments['errors'] != 'strict' or any(
                        call_name(candidate.func).rsplit('.', 1)[-1] == 'register_error'
                        or bindings.resolve(candidate.func) == ('import', 'codecs.register_error')
                        for candidate in bindings.calls):
                    return False
            return all(self.value_kind(value)[0] in primitive for value in
                       [*call.args, *(keyword.value for keyword in call.keywords)])
        return False

    def intrinsic_range_call(self, call):
        return (isinstance(call.func, ast.Name) and call.func.id == 'range'
                and self.builtin_is_unshadowed('range')
                and not self.ownership_bindings().dynamic_namespace
                and not self.ownership_bindings().builtin_namespace
                and 'range' not in self.ownership_bindings().member_writes
                and 1 <= len(call.args) <= 3 and not call.keywords
                and not any(isinstance(argument, ast.Starred) for argument in call.args))

    def intrinsic_string_join(self, call):
        """Resolve join from the already evaluated exact builtin receiver.

        A name or expression is sufficient only when the value lattice proves
        an exact str. An annotation, subclass, similarly named method, or a
        later assignment to the receiver cannot supply that proof.
        """
        if (not isinstance(call.func, ast.Attribute) or call.func.attr != 'join'
                or len(call.args) != 1 or isinstance(call.args[0], ast.Starred) or call.keywords):
            return False
        receiver = call.func.value
        if isinstance(receiver, ast.Constant) and isinstance(receiver.value, str):
            return True
        bindings = self.ownership_bindings()
        return (not bindings.dynamic_namespace and not bindings.builtin_namespace
                and self.value_kind(receiver)[0] == 'str')

    def string_join_facts(self, call):
        """Captured text facts for an intrinsic join over builtin strings."""
        if (not self.intrinsic_string_join(call)
                or self.ownership_bindings().dynamic_namespace
                or self.ownership_bindings().builtin_namespace):
            return None
        argument = call.args[0]
        facts = self.value_facts(argument)
        kind, element = self.fact_kinds(facts)
        if kind not in {'list', 'tuple', 'str'} or element != 'str' or self.generator_refs(facts):
            return None
        if kind == 'list' and not (isinstance(argument, (ast.List, ast.ListComp))
                                  or isinstance(argument, ast.Name) and argument.id in self.exclusive_lists):
            return None
        if self.string_join_uses_separator(argument):
            facts = self.join_value_facts(facts, self.value_facts(call.func.value))
        return facts

    def string_join_uses_separator(self, argument, references=None):
        """Whether two yielded elements remain possible before consumption.

        A separator contributes no text to an empty or singleton join. Use
        only literal cardinality bounds (filters can decrease them) and known
        exhausted cursors. Unknown iterables retain the separator's SQL facts.
        """
        def bound(value):
            self.step()
            if (isinstance(value, (ast.List, ast.Tuple))
                    and not any(isinstance(item, ast.Starred) for item in value.elts)):
                return min(2, len(value.elts))
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return min(2, len(value.value))
            return 2

        if references is None:
            return bound(argument) > 1
        for identity in references:
            if self.generator_phases.get(identity) == frozenset({'done'}):
                continue
            if not isinstance(identity, ast.GeneratorExp):
                return True
            maximum = 1
            for generator in identity.generators:
                maximum = min(2, maximum * bound(generator.iter))
            if maximum > 1:
                return True
        return False

    def regex_result_shape(self, call):
        """Selected genuine stdlib regex results, without a spelling shortcut.

        Match offsets are integers even when their input text is tainted.
        Imported factories need a closed namespace and literal patterns;
        unknown receivers, replacement functions and dynamic flags provide
        no proof. This models successful result types, not callback purity.
        """
        if not isinstance(call.func, (ast.Name, ast.Attribute)):
            return None
        if isinstance(call.func, ast.Attribute) and call.func.attr not in {
                'compile', 'match', 'fullmatch', 'search', 'finditer', 'start', 'end', 'span'}:
            return None
        if any(isinstance(arg, ast.Starred) for arg in call.args) or call.keywords:
            return None
        if isinstance(call.func, ast.Attribute):
            receiver = self.value_kind(call.func.value)[0]
            if (receiver == 'regex-match' and call.func.attr in {'start', 'end', 'span'}
                    and len(call.args) <= 1 and all(isinstance(arg, ast.Constant)
                    and type(arg.value) in {int, str} for arg in call.args)):
                return ('tuple', 'number') if call.func.attr == 'span' else ('number', '')
            if (receiver == 'regex-pattern' and call.func.attr in {'match', 'fullmatch', 'search', 'finditer'}
                    and 1 <= len(call.args) <= 3 and all(self.value_kind(arg)[0] == 'number'
                                                       for arg in call.args[1:])):
                return ('iterator', 'regex-match') if call.func.attr == 'finditer' else ('regex-match', '')
        target = self.ownership_call_target(call)
        if not target or target[0] != 'import' or target[1] not in {
                're.compile', 're.match', 're.fullmatch', 're.search', 're.finditer'}:
            return None
        constructor = target[1] == 're.compile'
        if not (len(call.args) in ({1, 2} if constructor else {2, 3})
                and isinstance(call.args[0], ast.Constant)
                and type(call.args[0].value) in {str, bytes}
                and (len(call.args) == (1 if constructor else 2)
                     or isinstance(call.args[-1], ast.Constant) and type(call.args[-1].value) is int)):
            return None
        bindings = self.ownership_bindings()
        if 'regex_closed' not in self._ownership_syntax:
            closed = (not bindings.dynamic_namespace and not bindings.builtin_namespace
                      and not bindings.regex_namespace_escape)
            if not closed:
                self._ownership_syntax['regex_closed'] = False
                return None
            parents = bindings.parents
            flags = {'A', 'ASCII', 'DEBUG', 'I', 'IGNORECASE', 'L', 'LOCALE', 'M', 'MULTILINE',
                     'NOFLAG', 'S', 'DOTALL', 'U', 'UNICODE', 'X', 'VERBOSE'}
            imports = {name for scope in bindings.owner_scopes.values() for name, values in scope['names'].items()
                       for value in values if value and value[0] == 'import'
                       and (value[1] == 're' or value[1].startswith('re.'))}
            flag_targets = {'re.' + flag for flag in flags}
            for name in imports:
                for node in bindings.name_loads.get(name, ()):
                    self.step()
                    resolved = bindings.resolve(node)
                    if not resolved or resolved[0] != 'import' or not (
                            resolved[1] == 're' or resolved[1].startswith('re.')):
                        continue
                    current, parent = node, parents.get(node)
                    while isinstance(parent, ast.Attribute) and parent.value is current:
                        self.step()
                        if isinstance(parent.ctx, (ast.Store, ast.Del)) or parent.attr.startswith('_'):
                            closed = False
                        current, parent = parent, parents.get(parent)
                    selected = bindings.resolve(current)
                    if current not in bindings.direct_callees and not (
                            selected and selected[0] == 'import' and selected[1] in flag_targets):
                        closed = False
            self._ownership_syntax['regex_closed'] = closed
        if not self._ownership_syntax['regex_closed']:
            return None
        if constructor:
            return 'regex-pattern', ''
        return ('iterator', 'regex-match') if target[1] == 're.finditer' else ('regex-match', '')

    def string_result(self, call):
        """Prove exact string returns without trusting annotations or names.

        A literal string's join cannot dispatch to an overridden method. A
        stable local callable may use that result on every return, including
        recursive calls elsewhere in its body. This summarizes only the
        returned object's shape; the normal visitor still checks its body,
        captures, callbacks, escapes and SQL sinks.
        """
        def intrinsic(value):
            # This predicate inspects syntax alone. Share its immutable result
            # between projections; call-time values and effects are still
            # evaluated by the normal visitor on every execution.
            syntax = self._ownership_syntax.setdefault('intrinsic_string_syntax', {})
            if value in syntax:
                return syntax[value]
            pending = [value]
            while pending:
                self.step()
                node = pending.pop()
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    continue
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    pending.extend((node.left, node.right))
                    continue
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == 'join' and isinstance(node.func.value, ast.Constant)
                        and isinstance(node.func.value.value, str) and len(node.args) == 1
                        and not isinstance(node.args[0], ast.Starred) and not node.keywords):
                    continue
                syntax[value] = False
                return False
            syntax[value] = True
            return True
        if intrinsic(call):
            return True
        if not isinstance(call.func, ast.Name):
            return False
        target = self.ownership_call_target(call)
        if not target or target[0] != 'function' or target[2]:
            return False
        function = target[1]
        if function not in self._string_returns:
            bindings = self.ownership_bindings()
            safe = (isinstance(function, ast.FunctionDef) and not function.decorator_list
                    and bool(function.body) and isinstance(function.body[-1], ast.Return)
                    and not bindings.dynamic_namespace and '__code__' not in bindings.member_writes
                    and not bindings.builtin_namespace and function.name not in bindings.member_writes
                    and not any(reference not in bindings.direct_callees
                                and bindings.resolve(reference) == target
                                for reference in bindings.name_loads.get(function.name, ())))
            pending = list(function.body) if safe else []
            while pending and safe:
                self.step()
                node = pending.pop()
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    continue
                if isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await)):
                    safe = False
                elif isinstance(node, ast.Return):
                    safe = intrinsic(node.value)
                    pending.extend(ast.iter_child_nodes(node))
                else:
                    pending.extend(ast.iter_child_nodes(node))
            self._string_returns[function] = safe
        return self._string_returns[function]

    def remember_list_argument(self, expression):
        """Remember owned lists that an earlier argument may still reference."""
        if not self.exclusive_lists:
            return
        pending = [expression]
        while pending:
            self.step()
            node = pending.pop()
            if isinstance(node, ast.Name) and node.id in self.exclusive_lists:
                self._argument_list_reads.add((self._generator_scope[-1], node.id))
            elif isinstance(node, ast.IfExp):
                pending.extend((node.body, node.orelse))
            elif isinstance(node, ast.BoolOp):
                pending.extend(node.values)
            elif isinstance(node, ast.NamedExpr):
                pending.append(node.value)

    def immediate_generator_borrow(self, call):
        """Borrow a private list during an unaliased builtin consumer."""
        predicates = {'any', 'all'}
        consumers = predicates | {'sum', 'list', 'tuple', 'set', 'frozenset', 'sorted', 'min', 'max'}
        consumer = None
        if (isinstance(call.func, ast.Name) and call.func.id in consumers
                and self.builtin_is_unshadowed(call.func.id)):
            consumer = call.func.id
        elif (isinstance(call.func, ast.Attribute) and call.func.attr == 'fromkeys'
                and isinstance(call.func.value, ast.Name) and call.func.value.id == 'dict'
                and self.builtin_is_unshadowed('dict')):
            bindings = self.ownership_bindings()
            if not bindings.dynamic_namespace and not bindings.builtin_namespace:
                consumer = 'fromkeys'
        # A second argument can mutate/escape the list after generator creation.
        # Keep the existing one-argument lifetime proof for the new consumer.
        if (consumer not in consumers | {'fromkeys'}
                or len(call.args) != 1 or call.keywords
                or not isinstance(call.args[0], ast.GeneratorExp)):
            return set()
        generator = call.args[0]
        if (len(generator.generators) != 1 or generator.generators[0].is_async
                or not isinstance(generator.generators[0].iter, ast.Name)):
            return set()
        root = generator.generators[0].iter
        if root.id not in self.exclusive_lists:
            return set()
        for node in ast.walk(generator):
            self.step()
            if (node is not generator and isinstance(node, (ast.NamedExpr, ast.Lambda,
                    ast.GeneratorExp, ast.Await, ast.Yield, ast.YieldFrom))
                    or isinstance(node, ast.Call) and consumer in predicates
                    or isinstance(node, ast.Name) and node.id == root.id and node is not root):
                return set()
        return {root.id}

    def nonretaining_call_arguments(self, call):
        """Prove root-list non-retention, not a helper's returned SQL value."""
        arguments = [*call.args, *(keyword.value for keyword in call.keywords)]
        if (call in self._consuming_iterables and isinstance(call.func, ast.Name)
                and call.func.id in {'iter', 'reversed'} and self.builtin_is_unshadowed(call.func.id)
                and len(call.args) == 1 and not call.keywords
                and isinstance(call.args[0], ast.Name) and call.args[0].id in self.exclusive_lists):
            return {call.args[0]}
        if (not self.exclusive_lists or not isinstance(call.func, ast.Name)
                or self.builtin_is_unshadowed(call.func.id)
                or any(isinstance(argument, ast.Starred) for argument in call.args)
                or any(keyword.arg is None for keyword in call.keywords)
                or not any(isinstance(argument, ast.Name) and argument.id in self.exclusive_lists
                           for argument in arguments)):
            return set()
        bindings = self.ownership_bindings()
        target = self.ownership_call_target(call)
        if bindings.dynamic_namespace or not target or target[0] != 'function':
            return set()
        function = target[1]
        if (not isinstance(function, ast.FunctionDef) or function.decorator_list
                or function.name != call.func.id):
            return set()
        if function not in self._nonretaining_parameters:
            parents = {}
            forbidden = '__code__' in bindings.member_writes or any(
                reference not in bindings.direct_callees and bindings.resolve(reference) == target
                for reference in bindings.name_loads.get(function.name, ()))
            for parent in self.deferred_nodes(function):
                if (parent is not function and isinstance(parent, (
                        ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda, ast.GeneratorExp))
                        or isinstance(parent, (ast.Yield, ast.YieldFrom, ast.Await, ast.Global, ast.Nonlocal))
                        or isinstance(parent, ast.Call) and call_name(parent.func).rsplit('.', 1)[-1] in {
                            'locals', 'globals', 'vars', 'eval', 'exec', 'currentframe', '_getframe'}):
                    forbidden = True
                parents.update((child, parent) for child in ast.iter_child_nodes(parent))
            safe = set(_all_parameters(function)) if not forbidden else set()
            for node in parents:
                if not isinstance(node, ast.Name) or node.id not in safe:
                    continue
                self.step()
                current = node
                if not isinstance(node.ctx, ast.Load):
                    safe.discard(node.id)
                    continue
                while True:
                    parent = parents.get(current)
                    if (isinstance(parent, ast.Subscript) and parent.value is current
                            or isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not)
                            or isinstance(parent, (ast.If, ast.While, ast.IfExp)) and parent.test is current
                            or isinstance(parent, (ast.For, ast.comprehension)) and parent.iter is current):
                        break
                    if isinstance(parent, ast.BoolOp):
                        current = parent
                        continue
                    if (isinstance(parent, ast.Call) and len(parent.args) == 1 and not parent.keywords
                            and isinstance(parent.func, ast.Name)
                            and bindings.resolve(parent.func) == ('unbound', parent.func.id)):
                        if parent.func.id in {'len', 'bool', 'id', 'type'}:
                            break
                        if parent.func.id in {'iter', 'reversed'}:
                            current = parent
                            continue
                    safe.discard(node.id)
                    break
            self._nonretaining_parameters[function] = frozenset(safe)
        record = {'positional': _positional_parameters(function), 'bound_receiver': False}
        return {argument for name, argument in _bind_call_arguments(call, record).items()
                if name in self._nonretaining_parameters[function]}

    def seal_recursive_siblings(self, function):
        """Validate a sibling call SCC before lending its shared list cells.

        Provisional records live only in an isolated proof probe. Every member
        must independently pass the existing escape, namespace, input and
        capture checks before any record reaches the live interpreter.
        """
        if (not isinstance(function, ast.FunctionDef) or not self.exclusive_lists
                or not self._generator_scope or function in self._closure_groups):
            return set()
        bindings = self.ownership_bindings()
        owner = bindings.owner_scopes[function]['parent']
        if owner is None or owner['node'] is not self._generator_scope[-1]:
            return set()
        edges, pending = {}, [function]
        while pending:
            current = pending.pop()
            if current in edges:
                continue
            self.step()
            called = set()
            for node in self.deferred_nodes(current):
                if not isinstance(node, ast.Call):
                    continue
                target = self.ownership_call_target(node, captured=False)
                if (target and target[0] == 'function'
                        and bindings.owner_scopes[target[1]]['parent'] is owner
                        and target[1] not in self._sealed_closures):
                    called.add(target[1])
            edges[current] = called
            pending.extend(called - edges.keys())
        group = {function}
        while True:
            previous = group.copy()
            group.update(node for node, callees in edges.items() if callees.intersection(group))
            if previous == group:
                break
            self.step()
        if len(group) < 2:
            return set()
        group = frozenset(group)
        roots, captures, records = set(), set(), {}
        for member in group:
            local = frozenset(bindings.owner_scopes[member]['names'])
            loaded = {node.id for node in self.deferred_nodes(member)
                      if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
            indirect, free = set(), loaded - local
            for node in self.deferred_nodes(member):
                if isinstance(node, ast.Call):
                    target = self.ownership_call_target(node, captured=False)
                    if target and target[0] == 'function' and target[1] in self._sealed_closures:
                        record = self._sealed_closures[target[1]]
                        indirect.update(record[0])
                        free.update(record[2])
            roots.update(self.exclusive_lists.intersection(loaded | indirect) - local)
            captures.update(free)
            records[member] = local
        if not roots:
            return set()
        probe = self.flow_probe()
        probe._recursive_closures = self._recursive_closures.copy()
        for member, local in records.items():
            probe._sealed_closures[member] = (frozenset(roots), local, frozenset(captures))
        for member in group:
            if not probe.sealed_list_captures(member, closure_group=group):
                return set()
        for member in group:
            self._sealed_closures[member] = probe._sealed_closures[member]
            self._closure_groups[member] = group
        self._recursive_closures.update(group)
        return set(self._sealed_closures[function][0])

    def declared_closure_cells(self, function):
        """Lexical nonlocal declarations, never assignments guessed by name."""
        return frozenset(self.ownership_bindings().owner_scopes[function]['nonlocal_names'])

    def sealed_list_captures(self, function, *, allow_empty=False, closure_group=frozenset()):
        """Borrow a private enclosing list only for a nonescaping local closure."""
        if function in self._closure_groups and not closure_group:
            roots = self._sealed_closures[function][0]
            return set(roots) if roots.issubset(self.exclusive_lists) else set()
        self._sealed_closures.pop(function, None)
        self._closure_cell_writes.pop(function, None)
        self._recursive_closures.discard(function)
        if (not isinstance(function, ast.FunctionDef) or not self._generator_scope
                or not isinstance(self._generator_scope[-1], (ast.FunctionDef, ast.AsyncFunctionDef))):
            return set()
        nodes, parents = self.deferred_nodes(function), {}
        for parent in nodes:
            parents.update((child, parent) for child in ast.iter_child_nodes(parent))
        def own_scope(node):
            parent = parents.get(node)
            while parent is not None and parent is not function:
                if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    return False
                parent = parents.get(parent)
            return True
        local = set(_all_parameters(function)) | {node.id for node in nodes
                    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and own_scope(node)}
        local.update(node.name for node in nodes if node is not function
                     and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and own_scope(node))
        loaded = {node.id for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
        self._deferred_name_cache[function] = frozenset(loaded)
        writes = {node.func.value.id for node in nodes if isinstance(node, ast.Call) and own_scope(node)
                  and isinstance(node.func, ast.Attribute) and node.func.attr in {'append', 'extend', 'pop'}
                  and isinstance(node.func.value, ast.Name) and node.func.value.id not in local}
        writes.update(node.value.id for node in nodes if isinstance(node, ast.Subscript) and own_scope(node)
                      and isinstance(node.ctx, ast.Store) and isinstance(node.value, ast.Name)
                      and node.value.id not in local)
        if writes:
            self._closure_list_writes[function] = frozenset(writes)
        if (function.decorator_list
                or any(not isinstance(default, ast.Constant) for default in function.args.defaults)
                or any(default is not None and not isinstance(default, ast.Constant)
                       for default in function.args.kw_defaults)
                or function.args.vararg or function.args.kwarg):
            return set()
        indirect, captures = set(), set()
        cells = set(self.declared_closure_cells(function))
        if self._sealed_closures:
            bindings = self.ownership_bindings()
            for node in nodes:
                if isinstance(node, ast.Call) and own_scope(node):
                    called = self.ownership_call_target(node, captured=False)
                    if called and called[0] == 'function' and called[1] in self._sealed_closures:
                        indirect.update(self._sealed_closures[called[1]][0])
                        captures.update(self._sealed_closures[called[1]][2])
                        cells.update(self._closure_cell_writes.get(called[1], ()))
        if not allow_empty and not self.exclusive_lists.intersection(loaded | indirect):
            return set()
        bindings = self.ownership_bindings()
        # The binding index includes imports, exception/match bindings and
        # comprehension scopes; Name(Store) alone cannot identify locals.
        local = set(bindings.owner_scopes[function]['names']) - self.declared_closure_cells(function)
        roots = self.exclusive_lists.intersection(loaded | indirect) - local
        if not roots and not allow_empty:
            return set()
        target = ('function', function, False)
        owner = bindings.owner_scopes[function]['parent']
        if (cells and (closure_group or owner is None
                or not isinstance(owner['node'], (ast.FunctionDef, ast.AsyncFunctionDef))
                or not cells.issubset(owner['names']) or cells.intersection(local | roots))):
            # This transfer covers the immediate owner's immutable cells.
            # Mutable aliases, intervening owners and sibling SCC cells need
            # heap/cell identities, not a same-spelled local substitution.
            return set()
        if (bindings.dynamic_namespace or (bindings.lookup(function.name, owner) != target
                and self.live_local_function(function.name, owner) != target)
                or '__code__' in bindings.member_writes or any(
                    reference not in bindings.direct_callees and bindings.resolve(reference) == target
                    for reference in bindings.name_loads.get(function.name, ()))):
            return set()
        recursive = False
        for node in nodes:
            if (node is not function and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    or isinstance(node, ast.Lambda) and any(
                        isinstance(child, ast.Name) and child.id in roots for child in ast.walk(node))
                    or isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await, ast.Global))
                    or isinstance(node, ast.Name) and isinstance(node.ctx, ast.Del) and node.id in cells):
                return set()
            if isinstance(node, ast.GeneratorExp):
                first = node.generators[0].iter
                eager_copy = (isinstance(first, ast.Subscript) and isinstance(first.slice, ast.Slice)
                              and isinstance(first.value, ast.Name) and first.value.id in roots)
                eager_nodes = set(ast.walk(first)) if eager_copy else set()
                if any(isinstance(child, ast.Name) and child.id in roots and child not in eager_nodes
                       for child in ast.walk(node)):
                    return set()
            if isinstance(node, ast.Call):
                if call_name(node.func).rsplit('.', 1)[-1] in {
                        'locals', 'globals', 'vars', 'eval', 'exec', 'currentframe', '_getframe'}:
                    return set()
                called = self.ownership_call_target(node, captured=False)
                if (called and called[0] == 'function'
                        and bindings.owner_scopes[called[1]]['parent'] is owner):
                    if called[1] is function:
                        recursive = True
                        continue
                    # A previously sealed sibling can borrow the same owner
                    # cells. Caller locals may not stand in for its captures;
                    # recursive sibling cycles still need a separate summary.
                    sibling = self._sealed_closures.get(called[1])
                    if (sibling is None or called[1] in self._recursive_closures and called[1] not in closure_group
                            or local.intersection(sibling[2])):
                        return set()
                    if called[1] in closure_group:
                        recursive = True
            if not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in roots):
                continue
            parent = parents.get(node)
            if (isinstance(parent, ast.Subscript) and parent.value is node
                    and isinstance(parent.ctx, (ast.Load, ast.Store))):
                # Indexed stores use the same bounded private-list transfer
                # as append/extend. Unknown indices/iterables and escapes
                # still revoke ownership or refuse in store_list_item.
                continue
            if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
                continue
            if isinstance(parent, (ast.If, ast.While, ast.IfExp)) and parent.test is node:
                continue
            if isinstance(parent, ast.For) and parent.iter is node:
                continue
            if (isinstance(parent, ast.Call) and parent.args == [node] and not parent.keywords
                    and isinstance(parent.func, ast.Name)
                    and parent.func.id in {'len', 'bool', 'str', 'repr', 'id', 'type'}
                    and bindings.resolve(parent.func) == ('unbound', parent.func.id)):
                continue
            if isinstance(parent, ast.Attribute) and parent.value is node:
                call = parents.get(parent)
                if (isinstance(call, ast.Call) and call.func is parent and not call.keywords
                        and parent.attr in {'append', 'extend', 'pop'}
                        and (len(call.args) == 1 if parent.attr != 'pop' else not call.args)
                        and not any(isinstance(child, (ast.NamedExpr, ast.Starred))
                                    for argument in call.args for child in ast.walk(argument))):
                    continue
            return set()
        if not recursive and any(isinstance(node, ast.Raise) for node in nodes):
            return set()
        self._sealed_closures[function] = (frozenset(roots), frozenset(local),
                                           frozenset((loaded | indirect | captures | cells) - local))
        self._closure_cell_writes[function] = frozenset(cells)
        if recursive:
            self._recursive_closures.add(function)
        return roots

    def sealed_closure_call(self, node):
        if (not isinstance(node.func, ast.Name)
                or not (self._closure_list_writes or self._sealed_closures)
                or self.builtin_is_unshadowed(node.func.id)):
            return False
        target = self.ownership_call_target(node)
        if not target or target[0] != 'function':
            if (target and target[0] == 'ambiguous-function'
                    and any(site in self._sealed_closures for site in target[1]
                            if isinstance(site, ast.FunctionDef))):
                raise SQLFlowLimit('SQL closure callable lifetime is unresolved; analysis is incomplete')
            return False
        function = target[1]
        if function not in self._closure_list_writes and function not in self._sealed_closures:
            return False
        if function not in self._sealed_closures:
            if any(self.value_kind(ast.Name(id=name, ctx=ast.Load()))[0] == 'list'
                   for name in self._closure_list_writes.get(function, ())):
                raise SQLFlowLimit('SQL closure list ownership is unresolved; analysis is incomplete')
            return False
        roots, local, free = self._sealed_closures[function]
        cells = self._closure_cell_writes.get(function, frozenset())
        group = self._closure_groups.get(function, frozenset())
        if group and any(self.binding_sites.get(member) != frozenset({member}) for member in group):
            raise SQLFlowLimit('SQL recursive sibling definition order is unresolved; analysis is incomplete')
        if free.intersection(self._comprehension_locals):
            raise SQLFlowLimit('SQL closure lexical frame is unresolved; analysis is incomplete')
        owner = self._ownership_bindings.owner_scopes[function]['parent']['node']
        if not self._generator_scope or not roots.issubset(self.exclusive_lists):
            raise SQLFlowLimit('SQL closure list ownership is unresolved; analysis is incomplete')
        call_scope = (self._generator_scope if self._generator_scope[-1] is function else
                      (*self._generator_scope, function))
        if (owner is not self._generator_scope[-1]
                and not (function in self._recursive_closures and function is self._generator_scope[-1])):
            if owner not in self._generator_scope:
                raise SQLFlowLimit('SQL closure list ownership is unresolved; analysis is incomplete')
            boundary = self._generator_scope.index(owner) + 1
            for intervening in self._generator_scope[boundary:]:
                if (intervening not in self._sealed_closures
                        or intervening in self._recursive_closures and (
                            intervening not in self._closure_groups
                            or function in self._recursive_closures
                            and self._closure_groups.get(intervening) != group)
                        or self._ownership_bindings.owner_scopes[intervening]['parent']['node'] is not owner
                        or free.intersection(self._sealed_closures[intervening][1])):
                    raise SQLFlowLimit('SQL closure lexical frame is unresolved; analysis is incomplete')
            # Resolution and builtin shadowing follow the callee's lexical
            # parent, not the chain of sibling calls that reached this point.
            call_scope = (*self._generator_scope[:boundary], function)
        if any((scope, name) in self._iterated_lists for name in roots
               for scope in self._generator_scope):
            raise SQLFlowLimit('SQL closure mutation during list iteration is unsupported; analysis is incomplete')
        if any((scope, name) in self._argument_list_reads for name in roots
               for scope in self._generator_scope):
            raise SQLFlowLimit('SQL closure mutation during argument evaluation is unsupported; analysis is incomplete')
        arguments = _bind_call_arguments(node, {'positional': _positional_parameters(function)})
        positional = _positional_parameters(function)
        for name, default in zip(positional[len(positional) - len(function.args.defaults):], function.args.defaults):
            arguments.setdefault(name, default)
        for argument, default in zip(function.args.kwonlyargs, function.args.kw_defaults):
            if default is not None:
                arguments.setdefault(argument.arg, default)
        if (set(arguments) != set(_all_parameters(function))
                or any(isinstance(argument, ast.Starred) for argument in node.args)
                or any(keyword.arg is None for keyword in node.keywords)
                or any(self.generator_refs(self.value_facts(value)) for value in arguments.values())
                or any(self.generator_bindings.get(name) for name in free)):
            raise SQLFlowLimit('SQL closure inputs are unresolved; analysis is incomplete')
        if any(self.value_kind(ast.Name(id=name, ctx=ast.Load()))[0]
               not in {'number', 'str', 'none', 'scalar'} for name in cells):
            raise SQLFlowLimit('SQL closure cell alias is unresolved; analysis is incomplete')
        if function in self._recursive_closures:
            return self.recursive_closure_call(node, function, arguments, call_scope)
        incoming = self.sql_state()
        probe = self.flow_probe()
        probe._evaluated_values.clear()
        # NUL cannot occur in a Python identifier. A private lattice slot
        # carries the value only on actual return exits, including finally
        # overrides; it is never copied back into the caller's bindings.
        probe._return_slot = '\0sql_return'
        probe._generator_scope = call_scope
        probe.func_stack.append(function)
        for name in local:
            probe.bind_value_facts([name], (None, None, None, False, 'unknown'))
        for name, value in arguments.items():
            probe.bind_value_facts([name], self.value_facts(value))
        try:
            flow = probe.statements(function.body, probe.sql_state())
        finally:
            # A later unsupported effect cannot erase a sink already reached
            # with the call's real inputs. Preserve it on partial-result exits
            # just as recursive and generator-consumer summaries do.
            for identity, finding in probe._sink_risks.items():
                previous = self._sink_risks.get(identity)
                if previous is None or finding[0] == 'critical':
                    self._sink_risks[identity] = finding
        normal = self.join_sql_states(flow.get('normal'), flow.get('return'))
        if normal is None:
            raise SQLFlowLimit('SQL closure completion is unresolved; analysis is incomplete')
        def captured_state(source):
            result = self.flow_probe()
            result.restore_sql_state(incoming)
            probe.restore_sql_state(source)
            for name in roots:
                result.bind_value_facts([name], probe.value_facts(ast.Name(id=name, ctx=ast.Load())))
                result.binding_sites[name] = incoming[12].get(name, frozenset({None}))
                # The callee's exit store already records actual escapes.
                # An exception alone does not export a proved private list;
                # losing that proof here poisons later recursive iterations.
                if name in source[10]:
                    result.exclusive_lists.add(name)
            for name in cells:
                result.bind_value_facts([name], probe.value_facts(ast.Name(id=name, ctx=ast.Load())))
                result.binding_sites[name] = source[12].get(name, frozenset({None}))
            result.validated.intersection_update(source[8])
            return result.sql_state()
        self.restore_sql_state(captured_state(normal))
        self.invalidate_validation(roots | cells)
        self._attribute_epoch = max(self._attribute_epoch, probe._attribute_epoch)
        if 'raise' in flow:
            self._pending_raise = self.join_sql_states(self._pending_raise, captured_state(flow['raise']))
        returned = []
        if flow.get('return') is not None:
            probe.restore_sql_state(flow['return'])
            returned.append(probe.value_facts(ast.Name(id=probe._return_slot, ctx=ast.Load())))
        if flow.get('normal') is not None:
            returned.append((None, None, None, False, 'static'))
        if any(self.generator_refs(facts) for facts in returned):
            raise SQLFlowLimit('SQL closure generator escape is unsupported; analysis is incomplete')
        self._evaluated_values[node] = self.join_value_facts(*returned)
        return True

    def ownership_bindings(self):
        if self._ownership_syntax['bindings'] is None:
            self._ownership_syntax['bindings'] = SanitizerBindings(
                self._generator_scope[0], frozenset(), self._budget)
        self._ownership_bindings = self._ownership_syntax['bindings']
        return self._ownership_bindings

    def recursive_closure_call(self, call, function, arguments, call_scope):
        """Solve a self-recursive closure over finite may-value facts.

        Recursive edges contribute inputs instead of creating another Python
        frame. The summary joins captured-list effects across normal and
        exceptional exits; caller locals never become a callee's free cells.
        """
        roots, local, _ = self._sealed_closures[function]
        cells = self._closure_cell_writes.get(function, frozenset())
        affected = roots | cells
        actual = {name: self.value_facts(value) for name, value in arguments.items()}
        captured = {name: self.value_facts(ast.Name(id=name, ctx=ast.Load())) for name in affected}
        active = self._closure_worklist.get(function)
        if active is not None:
            for name, facts in actual.items():
                active['arguments'][name] = self.join_value_facts(active['arguments'][name], facts)
            for name, facts in captured.items():
                active['captures'][name] = self.join_value_facts(active['captures'][name], facts)
                sites = self.binding_sites.get(name, frozenset({None}))
                self.bind_value_facts([name], self.join_value_facts(facts, active['effects'][name]))
                self.binding_sites[name] = sites
                if name in active['owned']:
                    self.exclusive_lists.add(name)
            self.note_possible_raise()
            if active['returned'] is None:
                raise SQLNoNormalReturn()
            self._evaluated_values[call] = active['returned']
            return True
        summary = {'arguments': actual, 'captures': captured, 'effects': captured.copy(),
                   'owned': set(roots), 'returned': None}
        self._closure_worklist[function] = summary
        incoming = self.sql_state()
        try:
            while True:
                self.step()
                before = (summary['arguments'].copy(), summary['captures'].copy(),
                          summary['effects'].copy(), summary['owned'].copy(), summary['returned'])
                probe = self.flow_probe()
                probe._evaluated_values.clear()
                probe._return_slot = '\0sql_return'
                probe._generator_scope = call_scope
                probe.func_stack = [node for node in call_scope if isinstance(node, ast.FunctionDef)]
                for name in local:
                    probe.bind_value_facts([name], (None, None, None, False, 'unknown'))
                for name, facts in summary['arguments'].items():
                    probe.bind_value_facts([name], facts)
                for name, facts in summary['captures'].items():
                    probe.bind_value_facts([name], facts)
                    probe.binding_sites[name] = incoming[12].get(name, frozenset({None}))
                    if name in summary['owned']:
                        probe.exclusive_lists.add(name)
                try:
                    flow = probe.statements(function.body, probe.sql_state())
                finally:
                    for identity, finding in probe._sink_risks.items():
                        previous = self._sink_risks.get(identity)
                        if previous is None or finding[0] == 'critical':
                            self._sink_risks[identity] = finding
                for state in flow.values():
                    probe.restore_sql_state(state)
                    for name in affected:
                        summary['effects'][name] = self.join_value_facts(
                            summary['effects'][name], probe.value_facts(ast.Name(id=name, ctx=ast.Load())))
                    summary['owned'].intersection_update(state[10])
                returned = []
                if flow.get('return') is not None:
                    probe.restore_sql_state(flow['return'])
                    returned.append(probe.value_facts(ast.Name(id=probe._return_slot, ctx=ast.Load())))
                if flow.get('normal') is not None:
                    returned.append((None, None, None, False, 'static'))
                if any(self.generator_refs(facts) for facts in returned):
                    raise SQLFlowLimit('SQL recursive generator escape is unsupported; analysis is incomplete')
                if returned:
                    summary['returned'] = self.join_value_facts(
                        *([] if summary['returned'] is None else [summary['returned']]), *returned)
                after = (summary['arguments'], summary['captures'], summary['effects'],
                         summary['owned'], summary['returned'])
                if before == after:
                    break
        finally:
            self._closure_worklist.pop(function, None)
        for name in affected:
            self.bind_value_facts([name], self.join_value_facts(captured[name], summary['effects'][name]))
            self.binding_sites[name] = incoming[12].get(name, frozenset({None}))
            if name in summary['owned']:
                self.exclusive_lists.add(name)
        self.validated.clear()
        self.note_possible_raise()
        if summary['returned'] is None:
            raise SQLNoNormalReturn()
        self._evaluated_values[call] = summary['returned']
        return True

    def ownership_call_target(self, node, *, captured=True):
        if captured and node in self._evaluated_call_targets:
            return self._evaluated_call_targets[node]
        # Lexical identity is immutable across flow iterations and private
        # probes. Cache only that identity, never SQL facts or ownership.
        calls = self._ownership_syntax['calls']
        if node.func not in calls:
            calls[node.func] = self.ownership_bindings().resolve(node.func)
        resolved = calls[node.func]
        if resolved is None and isinstance(node.func, ast.Name):
            scope = self.ownership_bindings().scope_of.get(node.func)
            while scope is not None and node.func.id not in scope['names']:
                previous = scope['node']
                scope = scope['parent']
                if not isinstance(previous, ast.ClassDef):
                    while scope is not None and isinstance(scope['node'], ast.ClassDef):
                        scope = scope['parent']
            resolved = self.live_local_function(node.func.id, scope)
            if resolved is None:
                sites = self.binding_sites.get(node.func.id, frozenset())
                if any(isinstance(site, ast.FunctionDef) for site in sites):
                    resolved = 'ambiguous-function', sites
        return resolved

    def live_local_function(self, name, scope):
        """Resolve the executed definition, including later cleanup rebindings.

        A syntax-wide union loses a local helper when a finally block clears
        its name to break a closure cycle. The current finite binding-site
        set can prove the earlier calls, but only if the callable never
        escapes and no indirect store can replace that lexical cell.
        """
        bindings = self.ownership_bindings()
        if (scope is None or not isinstance(scope['node'], (ast.FunctionDef, ast.AsyncFunctionDef))
                or bindings.dynamic_namespace or name in bindings.indirect_rebindings
                or '__code__' in bindings.member_writes):
            return None
        sites = self.binding_sites.get(name, frozenset())
        if len(sites) != 1:
            return None
        function = next(iter(sites))
        if (not isinstance(function, ast.FunctionDef) or function.name != name
                or bindings.owner_scopes.get(function, {}).get('parent') is not scope):
            return None
        cache = self._ownership_syntax.setdefault('local_function_escapes', {})
        if function not in cache:
            escaped = False
            for reference in bindings.name_loads.get(name, ()):
                self.step()
                owner = bindings.scope_of.get(reference)
                while owner is not None and name not in owner['names']:
                    previous = owner['node']
                    owner = owner['parent']
                    if not isinstance(previous, ast.ClassDef):
                        while owner is not None and isinstance(owner['node'], ast.ClassDef):
                            owner = owner['parent']
                if owner is scope and reference not in bindings.direct_callees:
                    escaped = True
                    break
            cache[function] = escaped
        if cache[function]:
            return None
        return 'function', function, False

    def escape_lists(self, expressions):
        """Revoke ownership when an object can be retained through an alias."""
        if not self.exclusive_lists and not self.numeric_regions:
            return
        pending = list(expressions)
        while pending:
            self.step()
            child = pending.pop()
            reference = self.numeric_reference(child) if isinstance(child, ast.expr) else None
            if reference is not None:
                self.retire_numeric_region(reference[0])
                raise SQLFlowLimit('SQL numeric list alias escape is unresolved; analysis is incomplete')
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                self.exclusive_lists.discard(child.id)
            elif isinstance(child, ast.IfExp):
                # The test is evaluated for truth, not returned as an alias.
                # Its calls/stores were already visited for eager effects.
                pending.extend((child.body, child.orelse))
            elif isinstance(child, ast.UnaryOp) and isinstance(child.op, ast.Not):
                # `not` always returns bool, never its operand. Other unary
                # operators may use user overloads and retain normal handling.
                continue
            elif isinstance(child, (ast.Subscript, ast.Call)):
                # Selecting an item does not export its owning list. A fresh
                # exclusive list cannot contain itself. Call argument and
                # receiver escapes have already run in visit_Call.
                continue
            else:
                pending.extend(ast.iter_child_nodes(child))

    def fresh_list(self, value):
        if isinstance(value, ast.IfExp):
            self.step()
            return self.fresh_list(value.body) and self.fresh_list(value.orelse)
        if isinstance(value, ast.Subscript) and isinstance(value.slice, ast.Slice):
            # A proved builtin list slice allocates distinct outer storage.
            # Item reads can return existing mutable objects, so they must
            # never acquire this ownership merely from their result kind.
            return self.value_kind(value)[0] == 'list'
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mult):
            # Repetition allocates a new outer list. It copies element
            # references, which retain their existing may-flow facts; it
            # does not alias the source list's mutable sequence storage.
            return self.value_kind(value)[0] == 'list'
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            # Both literal/constructed operands have unaliased outer storage;
            # concatenation allocates another list. Do not lend stale element
            # facts from an escaped operand merely because + returns a list.
            return (self.value_kind(value)[0] == 'list'
                    and self.fresh_list(value.left) and self.fresh_list(value.right))
        return (isinstance(value, (ast.List, ast.ListComp)) or
                isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id == 'list' and self.builtin_is_unshadowed('list')
                and self.value_kind(value)[0] == 'list')

    def fresh_list_targets(self, target, value):
        if isinstance(target, ast.Name) and self.fresh_list(value):
            scope = self._generator_scope[-1] if self._generator_scope else None
            if (not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
                    or target.id in self.deferred_list_captures
                    or self.captured_list_names(scope).intersection({target.id, '*'})):
                return set()
            return {target.id}
        if (isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List))
                and len(target.elts) == len(value.elts)
                and not any(isinstance(item, ast.Starred) for item in target.elts + value.elts)):
            self.step()
            return set().union(*(self.fresh_list_targets(left, right)
                                 for left, right in zip(target.elts, value.elts)))
        return set()

    def captured_list_names(self, scope):
        bindings = self._ownership_syntax['bindings']
        if scope not in self._list_captures and bindings is not None and scope in bindings.owner_scopes:
            # The binding walk has already classified the same immutable
            # scope and its nested reflection barriers. Do not walk it again
            # just because a later projection needs list ownership metadata.
            self._list_captures[scope] = bindings.owner_scopes[scope]['capture_barriers']
        if scope not in self._list_captures:
            names, pending = set(), list(scope.body)
            while pending:
                self.step()
                child = pending.pop()
                if isinstance(child, (ast.Global, ast.Nonlocal)):
                    names.update(child.names)
                elif isinstance(child, ast.Name) and child.id in {'locals', 'globals', 'vars', 'exec', 'eval'}:
                    names.add('*')
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                        ast.Lambda, ast.GeneratorExp)):
                    # Reflection in deferred code can expose the caller's
                    # frame too. Ordinary captures are recorded when that
                    # closure/generator is actually created on this path.
                    for nested in self.deferred_nodes(child):
                        if isinstance(nested, ast.Name) and nested.id in {'locals', 'globals', 'vars', 'exec', 'eval'}:
                            names.add('*')
                else:
                    pending.extend(ast.iter_child_nodes(child))
            self._list_captures[scope] = frozenset(names)
        return self._list_captures[scope]

    def defer_lists(self, expressions):
        # Exclusive ownership is granted only to function-local lists. A
        # module/class cannot acquire that proof, so collecting every name
        # in its function definitions adds work without tracking any owner.
        if (not self._generator_scope or not isinstance(
                self._generator_scope[-1], (ast.FunctionDef, ast.AsyncFunctionDef))):
            return
        for expression in expressions:
            self.step()
            if expression not in self._deferred_name_cache:
                self.deferred_nodes(expression)
            # Only lexical names are memoized. SQL values, validation proofs
            # and generator cursor state are always recomputed from flow.
            captures = self._ownership_syntax.setdefault('lexical_deferred_captures', {})
            key = expression, self._generator_scope[-1]
            if key not in captures:
                bindings = self.ownership_bindings()
                names = set()
                for child in self.deferred_nodes(expression):
                    if not isinstance(child, ast.Name) or not isinstance(child.ctx, ast.Load):
                        continue
                    self.step()
                    scope = bindings.scope_of.get(child)
                    if scope is None:
                        names.add(child.id)
                        continue
                    while scope is not None and child.id not in scope['names']:
                        previous = scope['node']
                        scope = scope['parent']
                        # Methods and comprehension bodies do not close over
                        # the class dictionary. Match the resolver's lexical
                        # walk so a same-named class attribute cannot hide a
                        # capture of the enclosing function's list.
                        if not isinstance(previous, ast.ClassDef):
                            while scope is not None and isinstance(scope['node'], ast.ClassDef):
                                scope = scope['parent']
                    if scope is not None and scope['node'] is self._generator_scope[-1]:
                        names.add(child.id)
                captures[key] = frozenset(names)
            names = set(captures[key])
            if self._sealed_closures:
                indirect = set()
                helpers = {function.name for function in self._sealed_closures}
                for child in self.deferred_nodes(expression):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load) and child.id in helpers:
                        self.step()
                        target = self.ownership_bindings().resolve(child)
                        if target and target[0] == 'function' and target[1] in self._sealed_closures:
                            # Deferred code captures a helper's closure cells
                            # too, even when it never spells the list's name.
                            names.update(self._sealed_closures[target[1]][0])
                            indirect.update(self._sealed_closures[target[1]][0])
                if indirect and isinstance(expression, ast.FunctionDef):
                    self._closure_list_writes[expression] = frozenset(indirect).union(
                        self._closure_list_writes.get(expression, ()))
            self.deferred_list_captures.update(names)
            self.exclusive_lists.difference_update(names)
            for name in names:
                reference = self.numeric_lists.get(name)
                if reference is not None:
                    bindings = self.ownership_bindings()
                    for child in self.deferred_nodes(expression):
                        if not (isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load) and child.id == name):
                            continue
                        scope = bindings.scope_of.get(child)
                        while scope is not None and name not in scope['names']:
                            scope = scope['parent']
                        if scope is not None and scope['node'] is reference[0][0]:
                            self.retire_numeric_region(reference[0])
                            raise SQLFlowLimit('SQL numeric list deferred capture is unresolved; analysis is incomplete')

    def deferred_nodes(self, expression):
        """One charged syntax walk, shared by capture and callable proofs."""
        if expression not in self._deferred_node_cache:
            nodes, names = [], set()
            for child in ast.walk(expression):
                self.step()
                nodes.append(child)
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    names.add(child.id)
            self._deferred_node_cache[expression] = tuple(nodes)
            self._deferred_name_cache[expression] = frozenset(names)
        return self._deferred_node_cache[expression]

    def assigned_generators(self, value):
        if isinstance(value, ast.GeneratorExp):
            return frozenset({value})
        if isinstance(value, ast.IfExp):
            self.step()
            return self.assigned_generators(value.body) | self.assigned_generators(value.orelse)
        return frozenset()

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


def _find_file(path: Path, *, max_steps=None) -> Iterable[tuple[str, Path, int, int, str]]:
    """Analyze one independent source, retaining findings before a refusal."""
    try:
        with tokenize.open(path) as stream:
            text = stream.read()
        tree = ast.parse(text, filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        reason = f'Cannot analyze Python SQL source {path}: {exc}; analysis is incomplete'
        component = {'file': str(path), 'symbol': '<module>', 'reason': reason}
        if getattr(exc, 'lineno', None) is not None:
            component['start_line'] = exc.lineno
            component['end_line'] = getattr(exc, 'end_lineno', None) or exc.lineno
        raise SQLFlowLimit(reason, components=(component,)) from exc
    # Every emitted SQL finding goes through this same sink predicate.
    # Walk all syntax, including deferred bodies and definition-time calls;
    # a matching name admits full analysis regardless of its arguments.
    # Decode and parse failures above must remain incomplete even when no
    # sink can be recognized. Applicable SQL flow keeps its ordinary budget.
    nodes = tuple(ast.walk(tree))
    if not any(isinstance(node, ast.Call) and (sql_sink_name(node) or reflected_sql_name(node)
                   or any(isinstance(argument, ast.Constant) and isinstance(argument.value, str)
                          and argument.value in EXECUTE_METHODS | {'extra'} for argument in node.args[:2]))
               or isinstance(node, ast.Attribute) and node.attr in EXECUTE_METHODS | {'extra'}
               or isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in EXECUTE_METHODS | {'extra'}
               or isinstance(node, ast.ImportFrom) and any(
                   alias.name in EXECUTE_METHODS | {'extra'} for alias in node.names)
               for node in nodes):
        return
    lines = text.splitlines()
    param_names, name_risk = build_provenance(tree)
    sanitizers = configured_sanitizers()
    # The mandatory lexical index is linear in source size. Keep the
    # ordinary small-file allowance, scale that floor for large modules,
    # and retain a hard ceiling. Explicit caller budgets remain exact.
    steps = max_steps if max_steps is not None else min(1_000_000, max(100_000, 2 * len(nodes)))
    budget = [steps]
    bindings = SanitizerBindings(tree, configured_sanitizer_targets(), budget)
    if (not any(sql_sink_name(call, bindings) or bindings.unresolved_sql_aliases(call)
                for call in bindings.calls) and not bindings.sql_facade_flow()[1]
            and not bindings.escaped_sql_methods()):
        return
    summaries = build_sanitizer_summaries(tree, sanitizers, text=text, budget=budget, bindings=bindings)
    analyzer = SQLInjectionAnalyzer(
        text,
        lines,
        param_names,
        name_risk,
        sanitizers,
        summaries,
        max_steps=steps,
        budget=budget,
        bindings=bindings,
    )
    analyzer._literal_statement_scopes = analyzer.literal_statement_scopes()
    failure = None
    try:
        analyzer.visit(tree)
    except SQLFlowLimit as exc:
        # The registry already retains streamed findings when a detector
        # fails. Preserve the evidence discovered before the unsupported
        # flow, then propagate the original incomplete-analysis error.
        failure = exc
    suppressions = build_index(text, "python") if may_have_markers(text) else SuppressionIndex()
    for line_no, code in analyzer.issues:
        if not suppressions.is_suppressed(line_no, RULE_CRITICAL):
            yield RULE_CRITICAL, path, line_no, 1, code[:240]
    for line_no, code in analyzer.warn_issues:
        if not suppressions.is_suppressed(line_no, RULE_WARNING):
            yield RULE_WARNING, path, line_no, 1, code[:240]
    if failure is not None:
        raise failure


def find(files: Sequence[Path], *, max_steps=None) -> Iterable[tuple[str, Path, int, int, str]]:
    """Keep independent files visible while reporting every incomplete source.

    Each source owns its bindings, flow state and budget. A refusal cannot
    certify that source, but must not discard later files' proven findings.
    The final exception preserves fail-closed completion and an untruncated
    component list independently of the bounded human-readable examples.
    """
    failures = []
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            yield from _find_file(path, max_steps=max_steps)
        except SQLFlowLimit as exc:
            components = exc.components or ({'symbol': '<module>', 'reason': str(exc)},)
            failures.extend(dict(component, file=str(path)) for component in components)
    if failures:
        if len(failures) == 1:
            raise SQLFlowLimit(failures[0]['reason'], components=failures)
        examples = '; '.join(f"{component['file']}:{component['symbol']}: {component['reason']}"
                             for component in failures[:3])
        omitted = f'; and {len(failures) - 3} more failed files' if len(failures) > 3 else ''
        raise SQLFlowLimit(f'Python SQL analysis is incomplete in {len(failures)} file(s): '
                           + examples + omitted, components=failures)
