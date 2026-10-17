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

Same-file and previous-line `ubs:ignore` markers suppress a hit at the call.

Statement templates, raw predicates and SELECT mapping values retain distinct
facts through the existing bounded flow engine. Finite literal iterables keep
their exact trip counts; finally transforms abrupt as well as normal exits.
Exception matching and unknown callee/heap effects remain conservative. An
exhausted budget or unsupported exception-group flow is not a clean result.
"""
from __future__ import annotations

import ast
import os
import re
import tokenize
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.io import python_source_segment

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


def configured_sanitizers(environ=None):
    """Sanitizer names from the environment, expanded to their suffixes.

    A project writing `psycopg.sql.Identifier` means the same function that
    the code calls as `sql.Identifier(...)` after `from psycopg import sql`,
    so the configured name is stored with its suffixes and a call matches when
    any of its own suffixes is in the set.
    """
    raw = (environ if environ is not None else os.environ).get(SANITIZER_ENV, '')
    names = set()
    for item in raw.split(','):
        item = item.strip()
        if item:
            names.update(dotted_suffixes(item))
    return frozenset(names)


def is_sanitizer_call(node, sanitizers):
    """Whether `node` is a call to one of the configured sanitizers."""
    if not sanitizers or not isinstance(node, ast.Call):
        return False
    name = call_name(node.func)
    return bool(name) and bool(dotted_suffixes(name) & sanitizers)


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
    third parameters of a method whose first is `cls`, so the implicit
    receiver is dropped when the call goes through an attribute. `*args`
    stops positional binding: past it nothing can be matched to a name.
    """
    positional = list(record['positional'])
    if positional and positional[0] in ('self', 'cls') and isinstance(node.func, ast.Attribute):
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


def call_validated_segments(node, text, sanitizers, summaries):
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
    if is_sanitizer_call(node, sanitizers):
        for argument in list(node.args) + [keyword.value for keyword in node.keywords]:
            segment = python_source_segment(text, argument)
            if segment:
                segments.append(segment.strip())
        return segments

    name = call_name(node.func)
    if not name:
        return segments
    record = summaries.get(name.split('.')[-1])
    if not record:
        return segments
    bound = _bind_call_arguments(node, record)
    for parameter, suffixes in record['validates'].items():
        argument = bound.get(parameter)
        if argument is None:
            continue
        segment = python_source_segment(text, argument)
        if not segment:
            continue
        segment = segment.strip()
        for suffix in suffixes:
            segments.append(f'{segment}.{suffix}' if suffix else segment)
    return segments


def _function_validates(func, sanitizers, summaries):
    """Which of `func`'s own parameters reach a sanitizer, and as what.

    `{'config': {'pg_table', 'pg_schema'}, 'writeback_column': {''}}`. The
    empty suffix means the parameter itself was validated. Nested functions
    are skipped for the same reason `guarded_expressions` skips them.
    """
    parameters = _all_parameters(func)
    validates = {}
    if not parameters:
        return validates
    pending = list(func.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Call):
            direct = is_sanitizer_call(node, sanitizers)
            record = None
            if not direct:
                name = call_name(node.func)
                record = summaries.get(name.split('.')[-1]) if name else None
            if direct:
                arguments = list(node.args) + [keyword.value for keyword in node.keywords]
                pairs = [(argument, '') for argument in arguments]
            elif record:
                bound = _bind_call_arguments(node, record)
                pairs = [
                    (bound[parameter], suffix)
                    for parameter, suffixes in record['validates'].items()
                    if parameter in bound
                    for suffix in suffixes
                ]
            else:
                pairs = []
            for argument, suffix in pairs:
                rooted = rooted_attribute(argument)
                if rooted is None or rooted[0] not in parameters:
                    continue
                root, own_suffix = rooted
                combined = '.'.join(part for part in (own_suffix, suffix) if part)
                validates.setdefault(root, set()).add(combined)
        pending.extend(ast.iter_child_nodes(node))
    return validates


def build_sanitizer_summaries(tree, sanitizers, rounds=4):
    """Per-function-name summaries of which parameters reach a sanitizer.

    Recomputed a bounded number of times so a wrapper that calls a wrapper is
    reached (`_validate_all` -> `_validate_one` -> `validate_sql_identifier`)
    without letting a recursive definition iterate forever.

    Two functions in one module may share a name. Rather than guess which one
    a call meant, the name is dropped unless both take the same positional
    parameters, and then only what BOTH validate is kept — a summary must
    never claim a guard that one of the candidates does not perform.
    """
    summaries = {}
    if not sanitizers:
        return summaries
    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if not functions:
        return summaries

    for _ in range(rounds):
        current = {}
        dropped = set()
        for func in functions:
            validates = _function_validates(func, sanitizers, summaries)
            record = {'positional': _positional_parameters(func), 'validates': validates}
            existing = current.get(func.name)
            if existing is None:
                if func.name not in dropped:
                    current[func.name] = record
                continue
            if existing['positional'] != record['positional']:
                current.pop(func.name, None)
                dropped.add(func.name)
                continue
            merged = {}
            for parameter, suffixes in existing['validates'].items():
                shared = suffixes & record['validates'].get(parameter, set())
                if shared:
                    merged[parameter] = shared
            existing['validates'] = merged
        current = {name: record for name, record in current.items() if record['validates']}
        if current == summaries:
            break
        summaries = current
    return summaries


def guarded_expressions(func, text, sanitizers, summaries=None):
    """Source text of every expression a sanitizer validates in `func`.

    Maps the expression's source segment to the earliest line that validates
    it, so a sink can require the guard to come first. Nested functions are
    not descended into: a guard that runs in a closure does not dominate a
    sink in the enclosing body, and the conservative reading is the one that
    downgrades less.
    """
    guarded = {}
    if not sanitizers:
        return guarded
    summaries = summaries or {}
    pending = list(func.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Call):
            for key in call_validated_segments(node, text, sanitizers, summaries):
                line = node.lineno
                if key not in guarded or line < guarded[key]:
                    guarded[key] = line
        pending.extend(ast.iter_child_nodes(node))
    return guarded


def build_guarded_expressions(tree, text, sanitizers):
    """Per-function guarded-expression tables, keyed by function node id."""
    tables = {}
    if not sanitizers:
        return tables
    summaries = build_sanitizer_summaries(tree, sanitizers)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            guarded = guarded_expressions(node, text, sanitizers, summaries)
            if guarded:
                tables[id(node)] = guarded
    return tables


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


def has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


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
    def __init__(self, text, lines, param_names, name_risk, sanitizers=frozenset(), guarded_tables=None,
                 *, max_steps=100_000):
        self.text = text
        self.lines = lines
        self.param_names = param_names
        self.name_risk = name_risk
        self.sanitizers = sanitizers
        self.guarded_tables = guarded_tables or {}
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
        self._pending_raise = None
        # A loaded expression denotes its value *at evaluation time*. Later
        # argument/walrus writes must not change a value already captured by
        # a tuple, SQL call or bound format method. AST objects (not their
        # recycled numeric ids) key these bounded per-analysis snapshots.
        self._evaluated_values = {}

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
                max((fact[4] for fact in facts), key=RISK_ORDER.__getitem__, default='unknown'))

    @property
    def issues(self):
        return [(line, code) for risk, line, code in self._sink_risks.values() if risk == 'critical']

    @property
    def warn_issues(self):
        return [(line, code) for risk, line, code in self._sink_risks.values() if risk == 'warning']

    def step(self):
        self.remaining_steps -= 1
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
        return unsafe, weak, fragments, selects, templates, values

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
        self.statements(node.body, self.sql_state())

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
        parameters = _all_parameters(node)
        self.unsafe_sql_vars.difference_update(parameters)
        self.weak_sql_vars.difference_update(parameters)
        self.sql_template_vars.difference_update(parameters)
        for parameter in parameters:
            self.fragment_sql_vars.pop(parameter, None)
            self.select_sql_vars.pop(parameter, None)
            self.value_risks[parameter] = 'tainted'
        self.func_stack.append(node)
        try:
            self.statements(node.body, self.sql_state())
        finally:
            self.func_stack.pop()
            self.restore_sql_state(outer)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        # Defaults execute now; the deferred body has its own bindings and
        # must not mutate the defining scope or raise into its try block.
        self.visit(node.args)
        outer, enclosing_raise = self.sql_state(), self._pending_raise
        self.bind_value_facts(_all_parameters(node), (None, None, None, False, 'tainted'))
        self._pending_raise = None
        try:
            self.visit(node.body)
        finally:
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
        body = self.statements(node.body, outer)
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
                self.sql_template_vars.copy(), self.value_risks.copy())

    def restore_sql_state(self, state):
        (self.unsafe_sql_vars, self.weak_sql_vars, self.fragment_sql_vars,
         self.select_sql_vars, self.sql_template_vars, self.value_risks) = (part.copy() for part in state)

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
        for part, outer in zip(restored, enclosing):
            if isinstance(part, set):
                part.difference_update(names)
                part.update(outer.intersection(names))
            else:
                for name in names:
                    if name in outer:
                        part[name] = outer[name]
                    else:
                        part.pop(name, None)
        return restored

    def visit_ListComp(self, node):
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
        self.visit(first.iter)
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
        """Whether a sanitizer validated this exact expression before the sink.

        The comparison is on source text inside one function body, which is
        what the accepted pattern actually writes: the same
        `config.pg_table` is handed to the validator and then interpolated.
        A sink outside any function, an expression with no recoverable source
        segment, or a guard on a later line all answer no (GH #133).
        """
        if not self.sanitizers or not self.func_stack or self.sink_lineno is None:
            return False
        guarded = self.guarded_tables.get(id(self.func_stack[-1]))
        if not guarded:
            return False
        segment = python_source_segment(self.text, node)
        if not segment:
            return False
        at = guarded.get(segment.strip())
        return at is not None and at < self.sink_lineno

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
            if is_sanitizer_call(node, self.sanitizers):
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
                self.select_risk(value), self.has_sql_template(value), self.classify_expr(value))

    def bind_value_facts(self, names, facts):
        risk, fragment_risk, select_risk, template, provenance = facts
        self.store_sql_risk(names, risk)
        for name in names:
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
        self.note_possible_raise()
        # The sink's own first line is what a guard has to precede (GH #133).
        # Using the sink line rather than the interpolated value's line keeps
        # a guard written inside the same multi-line call from counting.
        is_sink = bool(list(self.sql_arguments(node)))
        previous_sink = self.sink_lineno
        if is_sink:
            self.sink_lineno = node.lineno
        try:
            self.visit(node.func)
            for argument in node.args:
                self.visit(argument)
            for keyword in node.keywords:
                self.visit(keyword.value)
            # All effects have now occurred, but each argument retains its
            # own evaluation-time value. Suppress findings, never execution.
            if is_sink and not has_ignore(self.lines, node.lineno):
                self.classify_sink(node)
        finally:
            self.sink_lineno = previous_sink
        self.note_possible_raise()

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
        analyzer = SQLInjectionAnalyzer(
            text,
            lines,
            param_names,
            name_risk,
            sanitizers,
            build_guarded_expressions(tree, text, sanitizers),
            max_steps=max_steps,
        )
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield RULE_CRITICAL, path, line_no, 1, code[:240]
        for line_no, code in analyzer.warn_issues:
            yield RULE_WARNING, path, line_no, 1, code[:240]
