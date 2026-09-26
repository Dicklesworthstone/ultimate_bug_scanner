"""Function-scoped Python taint analysis with local call summaries (bead D6).

The AST transfer functions use strong assignment updates, join control-flow
branches, and iterate loops and recursive function summaries to a fixpoint.
Facts retain source provenance and sink-specific sanitizers. Local helpers
summarize both returned values and parameters reaching a sink; analyzed code
is never imported or executed. Cross-file and dynamic dispatch are not modeled.

Emit dialects:
- main(argv) emits the legacy tabular dialect: one
  `rule_id<TAB>count<TAB>sample,sample,...` row per rule with hits
  (rule ids `py.taint.*`, at most 3 comma-joined samples per rule).
- run(ctx) yields one NDJSON finding per detection with rule ids
  `python.taint.{kind}` (registry lang prefix).
"""
from __future__ import annotations

import ast
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import build_index

ROOT: Path = Path()
BASE_DIR: Path = Path()
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
EXTS = {'.py', '.pyi'}
PATH_LIMIT = 5

SOURCE_PATTERNS = [
    re.compile(r"request\.(?:args|get_json|json|form|values|data|body|GET|POST|query_params|path_params|headers|cookies|META)\b", re.IGNORECASE),
    re.compile(r"flask\.request", re.IGNORECASE),
    re.compile(r"django\.http\.request", re.IGNORECASE),
    re.compile(r"input\s*\(", re.IGNORECASE),
    re.compile(r"raw_input\s*\(", re.IGNORECASE),
    re.compile(r"sys\.argv", re.IGNORECASE),
    re.compile(r"os\.environ", re.IGNORECASE),
    re.compile(r"event\['body'\]", re.IGNORECASE),
    re.compile(r"params\[[^\]]+\]", re.IGNORECASE),
]

SANITIZERS = {
    'html.escape': 'xss', 'django.utils.html.escape': 'xss',
    'django.utils.html.conditional_escape': 'xss', 'flask.escape': 'xss',
    'markupsafe.escape': 'xss', 'bleach.clean': 'xss',
    'shlex.quote': 'command',
}

KIND_BY_RULE = {f'py.taint.{kind}': kind for kind in ('xss', 'sql', 'command', 'eval')}


_PARAMETER_MARKERS = {
    f'{module}.{name}'
    for module in ('fastapi', 'fastapi.params', 'fastapi.param_functions')
    for name in ('Query', 'Path', 'Body', 'Form', 'Header', 'Cookie', 'File')
}
_DEPENDENCY_MARKERS = {
    f'{module}.{name}'
    for module in ('fastapi', 'fastapi.params', 'fastapi.param_functions')
    for name in ('Depends', 'Security')
}
_REQUEST_TYPES = {'fastapi.Request', 'starlette.requests.Request', 'fastapi.requests.Request',
                  'django.http.HttpRequest', 'flask.Request', 'werkzeug.wrappers.Request'}
_SERVICE_TYPES = {'fastapi.Response', 'starlette.responses.Response', 'fastapi.BackgroundTasks',
                  'starlette.background.BackgroundTasks', 'fastapi.security.SecurityScopes'}
_ROUTER_TYPES = {'fastapi.FastAPI', 'fastapi.APIRouter', 'fastapi.applications.FastAPI',
                 'fastapi.routing.APIRouter'}
_ROUTE_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'trace', 'api_route'}
_REQUEST_MEMBERS = {'args', 'get_json', 'json', 'form', 'values', 'data', 'body', 'GET', 'POST',
                    'query_params', 'path_params', 'headers', 'cookies', 'COOKIES', 'META'}


@dataclass(frozen=True)
class _FrameworkInput:
    kind: str
    name: str


def _imported_name(node, bindings):
    """Resolve actual bindings, never a merely suggestive spelling."""
    if isinstance(node, ast.Name):
        target = bindings.get(node.id)
        return target if isinstance(target, str) else ''
    if isinstance(node, ast.Attribute):
        base = _imported_name(node.value, bindings)
        return f'{base}.{node.attr}' if base else ''
    return ''


def _framework_input(node, bindings, *, annotation_strings=False):
    """Interpret parameter metadata without evaluating annotations or imports."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if not annotation_strings:
            return None
        try:
            parsed = ast.parse(node.value, mode='eval').body
        except (SyntaxError, ValueError, RecursionError):
            return None
        # Do not recursively interpret strings containing more quoted strings.
        if isinstance(parsed, ast.Constant):
            return None
        return _framework_input(parsed, bindings, annotation_strings=True)
    if isinstance(node, ast.Name) and isinstance(bindings.get(node.id), _FrameworkInput):
        return bindings[node.id]
    name = _imported_name(node, bindings)
    if name in _REQUEST_TYPES:
        return _FrameworkInput('request', name)
    if name in _SERVICE_TYPES:
        return _FrameworkInput('service', name)
    if isinstance(node, ast.Call):
        name = _imported_name(node.func, bindings)
        if name in _PARAMETER_MARKERS:
            return _FrameworkInput('source', name)
        if name in _DEPENDENCY_MARKERS:
            # A dependency may supply a trusted service, not request data.
            return _FrameworkInput('dependency', name)
    if isinstance(node, ast.Subscript) and _imported_name(node.value, bindings) in {
            'typing.Annotated', 'typing_extensions.Annotated'}:
        parts = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
        for index in reversed(range(len(parts))):
            # Only the type position accepts a forward reference. Metadata
            # strings such as "Depends(service)" remain inert Python values.
            found = _framework_input(parts[index], bindings, annotation_strings=index == 0)
            if found is not None:
                return found
    return None


@dataclass(frozen=True)
class TaintTrace:
    source: str
    parameter: str | None = None
    sanitizers: frozenset[str] = frozenset()
    # Evidence is not part of the lattice. Growing a recursive provenance
    # path cannot keep a semantically stable fixpoint running indefinitely.
    path: tuple[str, ...] = field(default=(), compare=False)


Fact = frozenset[TaintTrace]
CLEAN: Fact = frozenset()


def join_facts(*facts: Fact) -> Fact:
    """Finite powerset join, retaining deterministic shortest evidence."""
    traces: dict[TaintTrace, TaintTrace] = {}
    for fact in facts:
        for trace in fact:
            previous = traces.get(trace)
            if previous is None or (len(trace.path), trace.path) < (len(previous.path), previous.path):
                traces[trace] = trace
    return frozenset(traces.values())


def _advance(fact: Fact, *steps: str) -> Fact:
    traces = []
    for trace in fact:
        path = list(trace.path)
        for step in steps:
            if not path or path[-1] != step:
                path.append(step)
        if len(path) > PATH_LIMIT:
            path = [path[0], *path[-(PATH_LIMIT - 1):]]
        traces.append(TaintTrace(trace.source, trace.parameter, trace.sanitizers, tuple(path)))
    return frozenset(traces)


def _sanitize(fact: Fact, kind: str) -> Fact:
    return frozenset(TaintTrace(t.source, t.parameter, t.sanitizers | {kind}, t.path) for t in fact)


def _safe_for(trace: TaintTrace, kind: str, label: str) -> bool:
    if kind == 'command' and label in {'subprocess executable', 'os executable'}:
        return False  # Quoting does not authorize an attacker-chosen executable.
    return kind in trace.sanitizers


class _State(dict):
    """Value facts and definitely-known callable identities at one program point."""

    def __init__(self, values=(), bindings=None):
        super().__init__(values)
        self.bindings = dict(bindings if bindings is not None else getattr(values, 'bindings', {}))

    def copy(self):
        return _State(self)

    def replace(self, other):
        self.clear()
        self.update(other)
        self.bindings = dict(other.bindings)

    def __eq__(self, other):
        return isinstance(other, _State) and dict.__eq__(self, other) and self.bindings == other.bindings


def _join_states(*states):
    reachable = [state for state in states if state is not None]
    if not reachable:
        return None
    names = set().union(*(state.keys() for state in reachable))
    bindings = {}
    for name in set().union(*(state.bindings.keys() for state in reachable)):
        candidates = [state.bindings.get(name) for state in reachable]
        bindings[name] = candidates[0] if all(value == candidates[0] for value in candidates) else None
    return _State({name: join_facts(*(state.get(name, CLEAN) for state in reachable)) for name in names}, bindings)


def _qualified(node: ast.AST, aliases: dict[str, object]) -> str:
    if isinstance(node, ast.Name):
        if node.id in aliases:
            target = aliases[node.id]
            if isinstance(target, str):
                return target
            if node.id in {'html', 'django', 'flask', 'markupsafe', 'bleach', 'shlex',
                           'subprocess', 'os', 'builtins', 'eval', 'exec', 'input', 'raw_input'}:
                return ''
        return node.id
    if isinstance(node, ast.Attribute):
        base = _qualified(node.value, aliases)
        return f'{base}.{node.attr}' if base else ''
    return ''


def _scope_nodes(scope):
    """Walk a lexical scope without reading the bodies of child scopes."""
    todo = list(reversed(scope.body))
    while todo:
        node = todo.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            todo.extend(reversed(list(ast.iter_child_nodes(node))))


def _local_names(scope) -> set[str]:
    names = set()
    for node in _scope_nodes(scope):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = scope.args
        names.update(arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs))
        names.update(arg.arg for arg in (args.vararg, args.kwarg) if arg is not None)
        for node in _scope_nodes(scope):
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                names.difference_update(node.names)
    return names


def _irrefutable_pattern(pattern) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _irrefutable_pattern(pattern.pattern)
    if isinstance(pattern, ast.MatchOr):
        return any(_irrefutable_pattern(alternative) for alternative in pattern.patterns)
    return False


@dataclass(frozen=True)
class FunctionSummary:
    returned: Fact = CLEAN
    # (kind, line, column, label, data). Symbolic parameters are substituted
    # at call sites; concrete request sources also stand alone in handlers.
    effects: tuple = ()


class _Flow:
    def __init__(self, engine, scope):
        self.engine = engine
        self.scope = scope
        self.returned = CLEAN
        self.effects = {}
        self.breaks = []
        self.continues = []
        self.exception_states = []
        self.stopped = []
        self.expression_facts = {}
        self.expression_bindings = {}

    def effect(self, kind, node, label, fact):
        unsafe = frozenset(trace for trace in fact if not _safe_for(trace, kind, label))
        key = (kind, node.lineno, node.col_offset + 1, label)
        if unsafe:
            self.effects[key] = join_facts(self.effects.get(key, CLEAN), unsafe)

    def assign(self, target, fact, state, value=None):
        if isinstance(target, ast.Name):
            state[target.id] = _advance(fact, target.id)
            state.bindings[target.id] = self.expression_bindings.get(value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
                for item, expression in zip(target.elts, value.elts):
                    self.assign(item, self.expression_facts.get(expression, CLEAN), state, expression)
            else:
                for item in target.elts:
                    self.assign(item, fact, state)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, fact, state)
        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            base = target.value
            while isinstance(base, (ast.Subscript, ast.Attribute)):
                base = base.value
            if isinstance(base, ast.Name):
                state[base.id] = join_facts(state.get(base.id, CLEAN), _advance(fact, base.id))

    def source(self, node, state):
        candidate = _qualified(node, state.bindings)
        if isinstance(node, ast.Call):
            candidate = _qualified(node.func, state.bindings) + '('
        elif isinstance(node, ast.Subscript):
            base = _qualified(node.value, state.bindings)
            if base == 'params':
                candidate = 'params[...]'
            elif base == 'event' and isinstance(node.slice, ast.Constant) and node.slice.value == 'body':
                candidate = "event['body']"
        if candidate.startswith('@request:'):
            qualified = candidate.removeprefix('@request:').removesuffix('(')
            request_type, _, member = qualified.rpartition('.')
            if request_type in _REQUEST_TYPES and member in _REQUEST_MEMBERS:
                return frozenset({TaintTrace(qualified, path=(qualified,))})
            return CLEAN
        for pattern in SOURCE_PATTERNS:
            match = pattern.search(candidate)
            if match:
                source = match.group(0)
                return frozenset({TaintTrace(source, path=(source,))})
        return CLEAN

    def bind(self, function, node, arguments, keywords, state):
        positional = [arg.arg for arg in (*function.args.posonlyargs, *function.args.args)]
        bound = {name: fact for name, fact in zip(positional, arguments)}
        for name, fact in keywords.items():
            if name is not None:
                bound[name] = fact
        defaults = dict(zip(positional[-len(function.args.defaults):], function.args.defaults)) if function.args.defaults else {}
        defaults.update((arg.arg, default) for arg, default in zip(function.args.kwonlyargs, function.args.kw_defaults)
                        if default is not None)
        for name, default in defaults.items():
            if name not in bound:
                bound[name] = self.engine.defaults.get(function, {}).get(name, CLEAN)
        expanded = join_facts(*(fact for arg, fact in zip(node.args, arguments) if isinstance(arg, ast.Starred)),
                              keywords.get(None, CLEAN))
        if expanded:
            for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
                bound[arg.arg] = join_facts(bound.get(arg.arg, CLEAN), expanded)
        if function.args.vararg:
            bound[function.args.vararg.arg] = join_facts(*arguments[len(positional):], expanded)
        if function.args.kwarg:
            accepted = set(positional) | {arg.arg for arg in function.args.kwonlyargs}
            bound[function.args.kwarg.arg] = join_facts(*(fact for name, fact in keywords.items() if name not in accepted))
        for name in self.engine.closures.get(function, ()):
            bound[f'@free:{name}'] = state.get(name, CLEAN)
        for name in self.engine.global_names:
            if (not isinstance(self.scope, ast.Module)
                    and (name in self.engine.locals.get(self.scope, set())
                         or name in self.engine.closures.get(self.scope, set()))):
                # The callee resolves globals in its defining module, not in
                # the caller's local/closure namespace. Carry that dependency
                # outward until a module call site supplies the actual value.
                bound[f'@global:{name}'] = frozenset({
                    TaintTrace(name, parameter=f'@global:{name}', path=(name,))
                })
            else:
                bound[f'@global:{name}'] = state.get(name, CLEAN)
        return bound

    @staticmethod
    def substitute(fact, bound, call_name):
        result = CLEAN
        for trace in fact:
            if trace.parameter is None:
                incoming = frozenset({trace})
            else:
                incoming = bound.get(trace.parameter, CLEAN)
                for sanitizer in trace.sanitizers:
                    incoming = _sanitize(incoming, sanitizer)
                steps = trace.path[1:] if trace.parameter.startswith('@') else trace.path
                incoming = _advance(incoming, call_name, *steps)
            result = join_facts(result, incoming)
        return result

    def call(self, node, state):
        name = _qualified(node.func, state.bindings)
        function = state.bindings.get(node.func.id) if isinstance(node.func, ast.Name) else None
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = None
        # Python evaluates the receiver/callable before argument expressions,
        # which may themselves reassign the receiver or callable name.
        receiver = self.expr(node.func.value, state) if isinstance(node.func, ast.Attribute) else CLEAN
        if isinstance(node.func, ast.Lambda):
            # Defaults execute when the callable is created, before arguments.
            # The body executes only once the lambda is actually called.
            self.expr(node.func, state)
        arguments = [self.expr(arg, state) for arg in node.args]
        keywords = {}
        keyword_nodes = {}
        for keyword in node.keywords:
            if keyword.arg is None and isinstance(keyword.value, ast.Dict):
                for key, value in zip(keyword.value.keys, keyword.value.values):
                    self.expr(key, state)
                    key_name = key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else None
                    keywords[key_name] = join_facts(keywords.get(key_name, CLEAN), self.expr(value, state))
                    keyword_nodes[key_name] = value
            else:
                keywords[keyword.arg] = join_facts(keywords.get(keyword.arg, CLEAN), self.expr(keyword.value, state))
                keyword_nodes[keyword.arg] = keyword.value
        if isinstance(node.func, ast.Lambda):
            bound = self.bind(node.func, node, arguments, keywords, state)
            local = state.copy()
            signature = node.func.args
            for arg in (*signature.posonlyargs, *signature.args, *signature.kwonlyargs,
                        signature.vararg, signature.kwarg):
                if arg is not None:
                    local[arg.arg] = _advance(bound.get(arg.arg, CLEAN), arg.arg)
                    local.bindings[arg.arg] = None
            return self.expr(node.func.body, local)
        if function is not None:
            bound = self.bind(function, node, arguments, keywords, state)
            summary = self.engine.summaries.get(function, FunctionSummary())
            for kind, line, column, label, fact in summary.effects:
                propagated = self.substitute(fact, bound, f'{function.name}()')
                propagated = frozenset(trace for trace in propagated if not _safe_for(trace, kind, label))
                key = (kind, line, column, label)
                if propagated:
                    self.effects[key] = join_facts(self.effects.get(key, CLEAN), propagated)
            return self.substitute(summary.returned, bound, f'{function.name}()')
        fact = join_facts(receiver, *arguments, *keywords.values(), self.source(node, state))
        first = arguments[0] if arguments else CLEAN

        def source_argument(*names):
            if arguments:
                return first
            return join_facts(keywords.get(None, CLEAN), *(keywords.get(key, CLEAN) for key in names))

        leaf = name.rsplit('.', 1)[-1]
        if leaf in {'render_template', 'render_template_string', 'HttpResponse', 'Response'}:
            label = 'render_template' if leaf.startswith('render_template') else ('Flask Response' if leaf == 'Response' else leaf)
            content = (join_facts(*arguments, *keywords.values()) if leaf.startswith('render_template')
                       else source_argument('content', 'response', 'body'))
            self.effect('xss', node, label, content)
        elif leaf in {'execute', 'executemany', 'text'} and name.split('.')[0] in {'cursor', 'session', 'conn', 'engine', 'db'}:
            query = source_argument('sql', 'query', 'statement', 'operation')
            self.effect('sql', node, 'SQL engine execute' if name.split('.')[0] in {'engine', 'db'} else 'SQL execute', query)
        elif name in {'subprocess.run', 'subprocess.Popen', 'subprocess.call', 'subprocess.check_output', 'subprocess.check_call'}:
            command = source_argument('args')
            command_node = node.args[0] if node.args else keyword_nodes.get('args')
            shell = keyword_nodes.get('shell')
            shell_true = isinstance(shell, ast.Constant) and bool(shell.value)
            shell_unknown = (shell is not None and not isinstance(shell, ast.Constant)) or None in keywords
            if isinstance(command_node, (ast.List, ast.Tuple)):
                # A list's first item selects the program or shell command;
                # later argument side effects must not re-evaluate that item.
                command = self.expression_facts.get(command_node.elts[0], CLEAN) if command_node.elts else CLEAN
            executable = join_facts(keywords.get('executable', CLEAN), keywords.get(None, CLEAN))
            executable_node = keyword_nodes.get('executable')
            fixed_executable = isinstance(executable_node, ast.Constant) and executable_node.value is not None
            if (not shell_true or shell_unknown) and not fixed_executable:
                executable = join_facts(executable, command)
            shell_code = command if shell_true or shell_unknown else CLEAN
            if executable:
                unsafe_shell = frozenset(trace for trace in shell_code if not _safe_for(trace, 'command', 'subprocess execution'))
                self.effect('command', node, 'subprocess executable', join_facts(executable, unsafe_shell))
            else:
                self.effect('command', node, 'subprocess execution', shell_code)
        elif name in {'os.system', 'os.popen', 'os.execv', 'os.execve', 'os.execvp', 'os.execvpe'}:
            self.effect('command', node, 'os executable' if leaf.startswith('exec') else 'os command execution', first)
        elif name in {'eval', 'exec', 'builtins.eval', 'builtins.exec'}:
            self.effect('eval', node, leaf, source_argument('source', 'object'))
        configurable_html = name == 'bleach.clean' and (
            len(node.args) > 1 or any(keyword.arg not in {'text', 'strip', 'strip_comments'} for keyword in node.keywords)
        )
        if name in SANITIZERS and not configurable_html:
            fact = _sanitize(fact, SANITIZERS[name])
        return fact

    def expr(self, node, state):
        # Callable identity belongs to the point before its arguments execute:
        # Query(alias := other) still constructs the originally bound marker.
        imported_call = _imported_name(node.func, state.bindings) if isinstance(node, ast.Call) else ''
        fact = self.expression(node, state)
        if node is not None:
            self.expression_facts[node] = fact
            binding = state.bindings.get(node.id) if isinstance(node, ast.Name) else None
            if isinstance(node, ast.Attribute):
                candidate = _qualified(node, state.bindings)
                if candidate in SANITIZERS:
                    binding = candidate
                imported = _imported_name(node, state.bindings)
                if imported in (_PARAMETER_MARKERS | _DEPENDENCY_MARKERS | _ROUTER_TYPES
                                | _REQUEST_TYPES | _SERVICE_TYPES):
                    binding = imported
            if isinstance(node, ast.Call):
                if imported_call in _ROUTER_TYPES:
                    binding = '@fastapi.router'
                elif imported_call in _PARAMETER_MARKERS:
                    binding = _FrameworkInput('source', imported_call)
                elif imported_call in _DEPENDENCY_MARKERS:
                    binding = _FrameworkInput('dependency', imported_call)
            if isinstance(node, ast.Subscript):
                binding = _framework_input(node, state.bindings)
            self.expression_bindings[node] = binding
        return fact

    def expression(self, node, state):
        if node is None or isinstance(node, ast.Constant):
            return CLEAN
        if isinstance(node, ast.Lambda):
            signature = node.args
            positional = [*signature.posonlyargs, *signature.args]
            defaults = {arg.arg: self.expr(value, state) for arg, value in
                        zip(positional[len(positional) - len(signature.defaults):], signature.defaults)}
            defaults.update({arg.arg: self.expr(value, state) for arg, value in
                             zip(signature.kwonlyargs, signature.kw_defaults) if value is not None})
            self.engine.defaults[node] = defaults
            return CLEAN
        if isinstance(node, ast.Compare):
            self.expr(node.left, state)
            self.expr(node.comparators[0], state)
            for comparator in node.comparators[1:]:
                executed = state.copy()
                self.expr(comparator, executed)
                state.replace(_join_states(state, executed))
            return CLEAN  # A comparison produces a bool, not executable text.
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            self.expr(node.operand, state)
            return CLEAN
        if isinstance(node, ast.Name):
            return state.get(node.id, CLEAN)
        if isinstance(node, ast.Call):
            return self.call(node, state)
        if isinstance(node, ast.NamedExpr):
            fact = self.expr(node.value, state)
            self.assign(node.target, fact, state, node.value)
            return fact
        if isinstance(node, ast.IfExp):
            self.expr(node.test, state)
            left, right = state.copy(), state.copy()
            fact = join_facts(self.expr(node.body, left), self.expr(node.orelse, right))
            state.replace(_join_states(left, right))
            return fact
        if isinstance(node, ast.BoolOp):
            fact = CLEAN
            exits = []
            continuation = state.copy()
            for value in node.values:
                fact = join_facts(fact, self.expr(value, continuation))
                exits.append(continuation.copy())
            state.replace(_join_states(*exits))
            return fact
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            nested = state.copy()
            for generator in node.generators:
                self.assign(generator.target, self.expr(generator.iter, nested), nested)
                for condition in generator.ifs:
                    self.expr(condition, nested)
            values = (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)
            fact = join_facts(*(self.expr(value, nested) for value in values))
            # Assignment expressions bind in the enclosing scope, while
            # ordinary comprehension targets remain local to the expression.
            for child in ast.walk(node):
                if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
                    name = child.target.id
                    state[name] = join_facts(state.get(name, CLEAN), nested.get(name, CLEAN))
                    state.bindings[name] = None
            return fact
        return join_facts(self.source(node, state), *(self.expr(child, state) for child in ast.iter_child_nodes(node)
                                              if isinstance(child, ast.expr)))

    def block(self, statements, state):
        for node in statements:
            if state is None:
                break
            if self.exception_states:
                self.exception_states[-1] = _join_states(self.exception_states[-1], state)
            state = self.statement(node, state)
        return state

    def statement(self, node, state):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Decorator expressions run before defaults. Preserve the real
            # router identity even if a later default rebinds its name.
            route = False
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and _imported_name(decorator.func, state.bindings) in {
                        f'@fastapi.router.{method}' for method in _ROUTE_METHODS}:
                    route = True
                self.expr(decorator, state)
            positional = [*node.args.posonlyargs, *node.args.args]
            defaults = dict(zip((arg.arg for arg in positional[-len(node.args.defaults):]), node.args.defaults)) if node.args.defaults else {}
            defaults.update((arg.arg, default) for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
                            if default is not None)
            default_facts = {}
            default_inputs = {}
            for name, default in defaults.items():
                default_facts[name] = self.expr(default, state)
                description = self.expression_bindings.get(default)
                if isinstance(description, _FrameworkInput):
                    default_inputs[name] = description
            self.engine.defaults[node] = default_facts
            self.engine.describe_framework(node, default_inputs, state.bindings, route)
            state[node.name] = CLEAN
            state.bindings[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for expression in (*node.bases, *node.decorator_list):
                self.expr(expression, state)
            for keyword in node.keywords:
                self.expr(keyword.value, state)
            self.block(node.body, state.copy())
            state[node.name] = CLEAN
            state.bindings[node.name] = node
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or alias.name.split('.')[0]
                state.bindings[local] = (f'{node.module}.{alias.name}' if isinstance(node, ast.ImportFrom)
                                         else alias.name if alias.asname else local)
                state[local] = CLEAN
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            if node.value is None:
                return state  # An annotation alone does not assign a value.
            fact = self.expr(node.value, state)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                self.assign(target, fact, state, node.value)
        elif isinstance(node, ast.AugAssign):
            self.assign(node.target, join_facts(self.expr(node.target, state), self.expr(node.value, state)), state)
        elif isinstance(node, ast.Assert):
            self.expr(node.test, state)
            # The message runs only on a raising path. Its sinks matter, but
            # its assignments cannot sanitize the normal continuation.
            self.expr(node.msg, state.copy())
        elif isinstance(node, ast.Expr):
            self.expr(node.value, state)
        elif isinstance(node, ast.Return):
            self.returned = join_facts(self.returned, self.expr(node.value, state))
            self.stopped.append(state.copy())
            return None
        elif isinstance(node, ast.Raise):
            self.expr(node.exc, state)
            self.expr(node.cause, state)
            self.stopped.append(state.copy())
            return None
        elif isinstance(node, ast.If):
            self.expr(node.test, state)
            return _join_states(self.block(node.body, state.copy()), self.block(node.orelse, state.copy()))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            return self.loop(node, state)
        elif isinstance(node, ast.Break):
            stopped = state.copy()
            self.breaks.append(stopped)
            self.stopped.append(stopped)
            return None
        elif isinstance(node, ast.Continue):
            stopped = state.copy()
            self.continues.append(stopped)
            self.stopped.append(stopped)
            return None
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                fact = self.expr(item.context_expr, state)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, fact, state)
            return self.block(node.body, state)
        elif isinstance(node, ast.Try) or (hasattr(ast, 'TryStar') and isinstance(node, ast.TryStar)):
            stopped_start = len(self.stopped)
            self.exception_states.append(state.copy())
            normal = self.block(node.body, state.copy())
            exceptional = self.exception_states.pop()
            completed = self.block(node.orelse, normal)
            handlers = [self.block(handler.body, exceptional.copy()) for handler in node.handlers]
            combined = _join_states(completed, *handlers)
            if node.finalbody:
                # Normal continuations and terminated branches each execute
                # finally. Keeping them separate prevents a return branch's
                # tainted locals from being lost in the normal-state join.
                for stopped in self.stopped[stopped_start:]:
                    final = self.block(node.finalbody, stopped.copy())
                    if final is not None:
                        stopped.replace(final)
                return self.block(node.finalbody, combined)
            return combined
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    state[target.id] = CLEAN
                    state.bindings[target.id] = None
        elif hasattr(ast, 'Match') and isinstance(node, ast.Match):
            subject = self.expr(node.subject, state)
            branches = []
            exhaustive = False
            for case in node.cases:
                branch = state.copy()
                for pattern in ast.walk(case.pattern):
                    name = getattr(pattern, 'name', None)
                    if isinstance(name, str):
                        branch[name] = _advance(subject, name)
                self.expr(case.guard, branch)
                branches.append(self.block(case.body, branch))
                if case.guard is None and _irrefutable_pattern(case.pattern):
                    exhaustive = True
                    break
            if not exhaustive:
                branches.append(state.copy())
            return _join_states(*branches)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.expr(child, state)
        return state

    def loop(self, node, state):
        outer_breaks, outer_continues = self.breaks, self.continues
        head = state.copy()
        exits = []
        while True:
            self.breaks, self.continues = [], []
            body = head.copy()
            if isinstance(node, ast.While):
                self.expr(node.test, body)
            else:
                self.assign(node.target, self.expr(node.iter, body), body)
            back = self.block(node.body, body)
            exits.extend(self.breaks)
            joined = _join_states(state, back, *self.continues)
            if joined == head:
                break
            head = joined
        self.breaks, self.continues = outer_breaks, outer_continues
        normal = self.block(node.orelse, head.copy())
        return _join_states(normal, *exits)

    def summary(self):
        return FunctionSummary(self.returned, tuple((*key, fact) for key, fact in sorted(self.effects.items())))


class _Analysis:
    def __init__(self, tree):
        self.tree = tree
        self.summaries = {}
        self.defaults = {}
        self.framework_inputs = {}
        self.parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        self.functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        self.locals = {scope: _local_names(scope) for scope in [tree, *self.functions]}
        self.global_names = self.locals[tree]
        self.closures = {}
        for function in self.functions:
            available = set()
            parent = self.enclosing(function)
            while parent is not None and not isinstance(parent, ast.Module):
                available.update(self.locals.get(parent, set()))
                parent = self.enclosing(parent)
            self.closures[function] = available - self.locals[function]

    def enclosing(self, node):
        node = self.parents.get(node)
        while node is not None and not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            node = self.parents.get(node)
        return node

    def describe_framework(self, function, default_inputs, bindings, route):
        inputs = {}
        for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
            description = (default_inputs.get(arg.arg)
                           or _framework_input(arg.annotation, bindings, annotation_strings=True))
            if description is None and route:
                description = _FrameworkInput('source', 'fastapi.request')
            if description is not None:
                inputs[arg.arg] = description
        # Capture import identities at the definition, before later rebinding.
        self.framework_inputs[function] = inputs

    def framework_bound(self, function):
        return {name: frozenset({TaintTrace(description.name, path=(description.name, name))})
                for name, description in self.framework_inputs.get(function, {}).items()
                if description.kind == 'source'}

    def analyze(self):
        # A summary contains only finite source/parameter/sanitizer facts.
        # Equality excludes evidence paths, so recursive helpers terminate
        # without a depth cap that would silently lose longer call chains.
        while True:
            module = _Flow(self, self.tree)
            globals_ = module.block(self.tree.body, _State())
            if globals_ is None:
                globals_ = _State()
            changed = False
            flows = [module]
            for function in self.functions:
                local = self.locals[function]
                flow = _Flow(self, function)
                state = _State({name: frozenset({TaintTrace(name, parameter=f'@global:{name}', path=(name,))})
                                for name in self.global_names if name not in local},
                               {name: target for name, target in globals_.bindings.items() if name not in local})
                for name in local:
                    state.bindings[name] = None
                arguments = function.args
                params = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
                params.extend(arg for arg in (arguments.vararg, arguments.kwarg) if arg is not None)
                for arg in params:
                    state[arg.arg] = frozenset({TaintTrace(arg.arg, parameter=arg.arg, path=(arg.arg,))})
                    description = self.framework_inputs.get(function, {}).get(arg.arg)
                    if description is not None and description.kind == 'request':
                        state.bindings[arg.arg] = '@request:' + description.name
                for name in self.closures[function]:
                    state[name] = frozenset({TaintTrace(name, parameter=f'@free:{name}', path=(name,))})
                    state.bindings[name] = None
                if function.name not in local and function.name not in state.bindings:
                    state.bindings[function.name] = function
                flow.block(function.body, state)
                summary = flow.summary()
                if summary != self.summaries.get(function, FunctionSummary()):
                    self.summaries[function] = summary
                    changed = True
                flows.append(flow)
            if not changed:
                effects = {}
                for flow in flows:
                    for key, fact in flow.effects.items():
                        if flow is not module:
                            bound = {f'@global:{name}': value for name, value in globals_.items()}
                            # Framework invocation is a separate entry point;
                            # summaries remain symbolic for ordinary callers.
                            bound.update(self.framework_bound(flow.scope))
                            fact = flow.substitute(fact, bound, flow.scope.name + '()')
                        concrete = frozenset(trace for trace in fact if trace.parameter is None)
                        if concrete:
                            effects[key] = join_facts(effects.get(key, CLEAN), concrete)
                return effects


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if not path.is_file(): continue
        if should_skip(path): continue
        if path.suffix.lower() in EXTS: yield path


def analyze_file(path, issues):
    for rule, line, _column, path_desc in scan_file_findings(path):
        try:
            rel = path.relative_to(ROOT)
        except ValueError:
            rel = path.name
        bucket = issues[rule]
        bucket['count'] += 1
        if len(bucket['samples']) < 3:
            bucket['samples'].append(f'{rel}:{line} {path_desc}')


def main(argv=None) -> int:
    """Emit the same detections as run(ctx), using the tabular entrypoint."""
    if argv is None:
        argv = sys.argv
    global ROOT, BASE_DIR
    ROOT = Path(argv[1]).resolve()
    BASE_DIR = ROOT if ROOT.is_dir() else ROOT.parent
    issues = defaultdict(lambda: {'count': 0, 'samples': []})
    for file_path in iter_files(ROOT):
        analyze_file(file_path, issues)
    for rule_id, data in issues.items():
        samples = ','.join(data['samples'])
        print(f"{rule_id}\t{data['count']}\t{samples}")
    return 0


_SEVERITY = {
    "xss": "critical",
    "sql": "critical",
    "command": "critical",
    "eval": "critical",
}

_MESSAGE = {
    "xss": "Unsanitized request data reaches HTML/response sinks",
    "sql": "User input flows into SQL execute() without parameters",
    "command": "User input reaches subprocess/os.system",
    "eval": "User input flows into eval/exec",
}


def scan_file_findings(path: Path):
    """Yield each reachable source-to-sink flow once at its sink location."""
    try:
        text = path.read_text(encoding='utf-8')
        tree = ast.parse(text, filename=str(path))
    except (OSError, UnicodeError, SyntaxError, ValueError):
        return
    suppressions = build_index(text, lang='python')
    effects = _Analysis(tree).analyze()
    for (kind, line, column, label), fact in sorted(effects.items(), key=lambda item: (item[0][1], item[0][2], item[0][0])):
        rule = f'py.taint.{kind}'
        if suppressions.is_suppressed(line, rule) or suppressions.is_suppressed(line, f'python.taint.{kind}'):
            continue
        trace = min(fact, key=lambda item: (len(item.path), item.path, item.source))
        path_desc = ' -> '.join((*trace.path, label))
        yield rule, line, column, path_desc


def run(ctx: RunContext) -> Iterable[dict]:
    for path in ctx.files:
        if path.suffix.lower() not in EXTS:
            continue
        if should_skip(path):
            continue
        rel = path.resolve()
        for rule, line, col, path_desc in scan_file_findings(path):
            kind = KIND_BY_RULE[rule]
            if not ctx.rule_enabled(f'python.taint.{kind}') or not ctx.rule_enabled(rule):
                continue
            yield {
                "rule": f"python.taint.{kind}",
                "path": str(rel),
                "line": line,
                "col": col,
                "layer": "taint",
                "lang": "python",
                "severity": _SEVERITY.get(kind, "warning"),
                "message": f"{_MESSAGE.get(kind, kind)} ({path_desc})",
            }


def _selftest_direct_source_sink(tmp_prefix: str = "ubs_core_taint_py_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "view.py"
        target.write_text(
            "render_template('hi.html', q=request.args.get('q'))\n",  # ubs:ignore
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="python", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "python.taint.xss", findings
    assert findings[0]["line"] == 1
    assert findings[0]["severity"] == "critical"
    assert "request.args -> render_template" in findings[0]["message"]


def _selftest_propagated_taint(tmp_prefix: str = "ubs_core_taint_py_prop_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "flow.py"
        target.write_text(
            "q = request.args.get('q')\n"
            "cursor.execute('SELECT * FROM t WHERE x=' + q)\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="python", files=[target])))
    assert len(findings) == 1, findings
    assert findings[0]["rule"] == "python.taint.sql", findings
    assert findings[0]["line"] == 2
    assert "request.args -> q -> SQL execute" in findings[0]["message"]


def _selftest_sanitizer_suppression(tmp_prefix: str = "ubs_core_taint_py_san_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "safe.py"
        target.write_text(
            "q = html.escape(request.args.get('q'))\n"
            "render_template('hi.html', q=q)\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="python", files=[target])))
    assert findings == [], findings


def _selftest_ignore_comment_suppression(tmp_prefix: str = "ubs_core_taint_py_ign_") -> None:
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "ignored.py"
        target.write_text(
            "# ubs:ignore\n"
            "render_template('hi.html', q=request.args.get('q'))\n",
            encoding="utf-8",
        )
        findings = list(run(RunContext(lang="python", files=[target])))
    assert findings == [], findings


def _selftest_main_emit_dialect(tmp_prefix: str = "ubs_core_taint_py_main_") -> None:
    import contextlib
    import io
    import tempfile

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "view.py"
        target.write_text(
            "q = request.args.get('q')\n"
            "eval(q)\n",  # ubs:ignore
            encoding="utf-8",
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = main(["x", str(tmp)])
        assert rc == 0
        out = buffer.getvalue()
    assert out == f"py.taint.eval\t1\tview.py:2 request.args -> q -> eval\n", repr(out)


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("direct_source_sink", _selftest_direct_source_sink),
    ("propagated_taint", _selftest_propagated_taint),
    ("sanitizer_suppression", _selftest_sanitizer_suppression),
    ("ignore_comment_suppression", _selftest_ignore_comment_suppression),
    ("main_emit_dialect", _selftest_main_emit_dialect),
)

register(Analyzer(layer="taint", lang="python", name="taint_py", run=run, selftests=SELF_TESTS))
