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
    def __init__(self, text, lines, param_names, name_risk):
        self.text = text
        self.lines = lines
        self.param_names = param_names
        self.name_risk = name_risk
        self.unsafe_sql_vars = set()
        self.weak_sql_vars = set()
        self.issues = []
        self.warn_issues = []

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
                return 'tainted'
            return self.name_risk.get(node.id, 'unknown')
        if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript, ast.Await)):
            return 'tainted'
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
        self.generic_visit(node)


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
        analyzer = SQLInjectionAnalyzer(text, lines, param_names, name_risk)
        analyzer.visit(tree)
        for line_no, code in analyzer.issues:
            yield RULE_CRITICAL, path, line_no, 1, code[:240]
        for line_no, code in analyzer.warn_issues:
            yield RULE_WARNING, path, line_no, 1, code[:240]
