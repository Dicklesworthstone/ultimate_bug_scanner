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
"""
from __future__ import annotations

import ast
import os
import re
from typing import Iterable, Sequence

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
EXECUTE_METHODS = {'execute', 'executemany', 'executescript', 'raw', 'read_sql', 'read_sql_query', 'scalar', 'scalars'}

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
            segment = ast.get_source_segment(text, argument)
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
        segment = ast.get_source_segment(text, argument)
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
    segment = ast.get_source_segment(text, node) or ''
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


def max_risk(a, b):
    return a if RISK_ORDER[a] >= RISK_ORDER[b] else b


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
    def __init__(self, text, lines, param_names, name_risk, sanitizers=frozenset(), guarded_tables=None):
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
        self.issues = []
        self.warn_issues = []

    def visit_FunctionDef(self, node):
        self.func_stack.append(node)
        self.generic_visit(node)
        self.func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

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
        segment = ast.get_source_segment(self.text, node)
        if not segment:
            return False
        at = guarded.get(segment.strip())
        return at is not None and at < self.sink_lineno

    def names_in(self, node):
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def unsafe_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.unsafe_sql_vars)

    def weak_names_in(self, node):
        return sorted(name for name in self.names_in(node) if name in self.weak_sql_vars)

    def classify_expr(self, node):
        # GH #94: provenance of one interpolated value. Names tainted by an
        # interpolated-SQL assignment count as tainted here too.
        if isinstance(node, ast.Constant):
            return 'static'
        if isinstance(node, ast.JoinedStr):
            risk = 'static'
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    risk = max_risk(risk, self.classify_expr(part.value))
            return risk
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return max_risk(self.classify_expr(node.left), self.classify_expr(node.right))
        if isinstance(node, ast.Name):
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
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            parts = list(node.args) + [kw.value for kw in node.keywords]
            sql_node = node.func.value
        else:
            return None
        if require_sql and not looks_like_sql(sql_node, self.text):
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
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            return True
        return any(self.contains_interpolation(child) for child in ast.iter_child_nodes(node))

    def sql_risk(self, node, require_sql=True):
        # Worst severity over the expression: None (safe), 'warning', 'critical'.
        worst = None
        if self.unsafe_names_in(node):
            return 'critical'
        if self.weak_names_in(node):
            worst = 'warning'
        for child in ast.walk(node):
            severity = self.interpolated_sql_severity(child, require_sql=require_sql)
            if severity == 'critical':
                return 'critical'
            if severity == 'warning':
                worst = 'warning'
        return worst

    def target_names(self, targets):
        names = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                names.extend(elt.id for elt in target.elts if isinstance(elt, ast.Name))
        return names

    def mark_assignment(self, names, value):
        risk = self.sql_risk(value)
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
        names = self.target_names(node.targets)
        if names:
            self.mark_assignment(names, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.mark_assignment([node.target.id], node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            risk = self.sql_risk(node.value)
            if node.target.id in self.unsafe_sql_vars or risk == 'critical':
                self.unsafe_sql_vars.add(node.target.id)
                self.weak_sql_vars.discard(node.target.id)
            elif node.target.id in self.weak_sql_vars or risk == 'warning':
                self.weak_sql_vars.add(node.target.id)
        self.generic_visit(node)

    def sql_argument(self, node):
        name = call_name(node.func)
        short = name.rsplit('.', 1)[-1]
        if short in EXECUTE_METHODS:
            return node.args[0] if node.args else None
        if short == 'extra':
            for keyword in node.keywords:
                if keyword.arg == 'where':
                    return keyword.value
        return None

    def visit_Call(self, node):
        if has_ignore(self.lines, node.lineno):
            self.generic_visit(node)
            return
        # The sink's own first line is what a guard has to precede (GH #133).
        # Using the sink line rather than the interpolated value's line keeps
        # a guard written inside the same multi-line call from counting.
        previous_sink = self.sink_lineno
        self.sink_lineno = node.lineno
        try:
            self.classify_sink(node)
        finally:
            self.sink_lineno = previous_sink
        self.generic_visit(node)

    def classify_sink(self, node):
        arg = self.sql_argument(node)
        if arg is not None:
            risk = self.sql_risk(arg)
            if risk == 'critical':
                self.issues.append((node.lineno, source_line(self.lines, node.lineno)))
            elif risk == 'warning':
                self.warn_issues.append((node.lineno, source_line(self.lines, node.lineno)))
        elif call_name(node.func).rsplit('.', 1)[-1] == 'extra':
            for keyword in node.keywords:
                if keyword.arg == 'where' and self.contains_interpolation(keyword.value):
                    risk = self.sql_risk(keyword.value, require_sql=False)
                    if risk == 'critical':
                        self.issues.append((node.lineno, source_line(self.lines, node.lineno)))
                    elif risk == 'warning':
                        self.warn_issues.append((node.lineno, source_line(self.lines, node.lineno)))
                    break


def find(files: Sequence[Path]) -> Iterable[tuple[str, Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
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
        )
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield RULE_CRITICAL, path, line_no, 1, code[:240]
        for line_no, code in analyzer.warn_issues:
            yield RULE_WARNING, path, line_no, 1, code[:240]
