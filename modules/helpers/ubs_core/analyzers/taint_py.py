"""Function-scoped Python taint analysis with local call summaries (bead D6).

The AST transfer functions use strong assignment updates, join control-flow
branches, and iterate loops and recursive function summaries to a fixpoint.
Facts retain source provenance and sink-specific sanitizers. Local helpers
summarize both returned values and parameters reaching a sink; analyzed code
is never imported or executed. Cross-file and arbitrary dynamic dispatch are
not modeled; known callable aliases and their finite branch alternatives are.
Mutable objects use a finite, field-insensitive heap: aliases share writes,
and local call summaries propagate output-parameter and captured-object writes.
Pending returns, raises, breaks and continues pass through cleanup before
being summarized; explicit exception payloads flow through typed handlers.

Emit dialects:
- main(argv) emits the legacy tabular dialect: one
  `rule_id<TAB>count<TAB>sample,sample,...` row per rule with hits
  (rule ids `py.taint.*`, at most 3 comma-joined samples per rule).
- run(ctx) yields one NDJSON finding per detection with rule ids
  `python.taint.{kind}` (registry lang prefix).
"""
from __future__ import annotations

import ast
import builtins
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
    dependency: ast.FunctionDef | ast.AsyncFunctionDef | None = None


def _imported_name(node, bindings):
    """Resolve actual bindings, never a merely suggestive spelling."""
    if isinstance(node, ast.Name):
        target = bindings.get(node.id)
        return target if isinstance(target, str) else ''
    if isinstance(node, ast.Attribute):
        base = _imported_name(node.value, bindings)
        return f'{base}.{node.attr}' if base else ''
    return ''


def _keyword_argument(node, name):
    """Find an explicit keyword or its equivalent in a literal ** mapping."""
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
        if keyword.arg is None and isinstance(keyword.value, ast.Dict):
            for key, value in zip(keyword.value.keys, keyword.value.values):
                if isinstance(key, ast.Constant) and key.value == name:
                    return value
    return None


def _dependency_target(node, bindings, evaluated=None):
    argument = node.args[0] if node.args else _keyword_argument(node, 'dependency')
    if evaluated is not None:
        target = evaluated.get(argument)
    else:
        target = bindings.get(argument.id) if isinstance(argument, ast.Name) else None
    return target if isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef)) else None


def _framework_input(node, bindings, *, annotation_strings=False, evaluated=None):
    """Interpret parameter metadata without evaluating annotations or imports."""
    if evaluated is not None and isinstance(evaluated.get(node), _FrameworkInput):
        return evaluated[node]
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
            return _FrameworkInput('dependency', name, _dependency_target(node, bindings, evaluated))
    if isinstance(node, ast.Subscript) and _imported_name(node.value, bindings) in {
            'typing.Annotated', 'typing_extensions.Annotated'}:
        parts = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
        for index in reversed(range(len(parts))):
            # Only the type position accepts a forward reference. Metadata
            # strings such as "Depends(service)" remain inert Python values.
            found = _framework_input(parts[index], bindings, annotation_strings=index == 0, evaluated=evaluated)
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
# Allocation sites are AST nodes, while strings name symbolic argument,
# closure, or module objects. Both sets are finite even inside recursion.
References = frozenset[ast.AST | str]
NO_REFERENCES: References = frozenset()


@dataclass(frozen=True)
class _BoundCallable:
    name: str
    references: References
    receiver: Fact = CLEAN


@dataclass(frozen=True)
class _LiteralString:
    """A value is not an import/callable identity just because it is text."""
    value: str


@dataclass(frozen=True)
class _SymbolicValue:
    parameter: str


@dataclass(frozen=True)
class _ArgumentVector:
    # Only fixed syntactic constructions have a shape. Unknown writes/escapes
    # invalidate it instead of guessing which position a heap fact describes.
    operands: tuple


@dataclass(frozen=True)
class _ProcessInput:
    kind: str


@dataclass(frozen=True)
class _DeferredCall:
    """Known coroutine creation captures arguments, not execution effects."""

    function: ast.AsyncFunctionDef
    call: ast.Call
    arguments: tuple
    references: tuple
    values: tuple = ()

# Preserve the existing conventional unimported names, but never restore one
# after a local assignment/parameter has explicitly shadowed it.
_IMPLICIT_IDENTITIES = frozenset({
    'eval', 'exec', 'input', 'raw_input', 'print', 'str', 'builtins',
    'html', 'django', 'flask', 'markupsafe', 'bleach', 'shlex', 'subprocess', 'os', 'asyncio',
    'sys', 'request', 'cursor', 'session', 'conn', 'engine', 'db',
    'render_template', 'render_template_string', 'HttpResponse', 'Response',
})


def _implicit_identity(name):
    if name in _IMPLICIT_IDENTITIES:
        return name
    value = getattr(builtins, name, None)
    if isinstance(value, type) and issubclass(value, BaseException):
        return 'builtins.' + name
    return None


def _binding_choices(binding):
    return binding if isinstance(binding, frozenset) else frozenset({binding})


def _join_bindings(*bindings):
    choices = frozenset().union(*(_binding_choices(binding) for binding in bindings))
    if len(choices) == 1:
        return next(iter(choices))
    return choices  # Empty means no known return yet; None means unknown.


def _without_object_contract(binding):
    return _join_bindings(*(None if isinstance(value, (_ArgumentVector, _ProcessInput)) else value
                            for value in _binding_choices(binding)))


def _extend_qualifier(base: str, attribute: str) -> str:
    """Keep name identities finite without dropping value or receiver facts.

    Recognizers need an exact known API name, the root SQL handle, the final
    method, or up to three trailing source components. A non-identifier marker
    prevents long unknown paths from acquiring an exact sanitizer identity.
    """
    name = f'{base}.{attribute}'
    components = name.split('.')
    width = max(4, *(candidate.count('.') + 1 for candidate in SANITIZERS))
    if len(components) <= width:
        return name
    return '.'.join((components[0], '<unknown>', *components[-3:]))


def _call_name(function):
    return '<lambda>()' if isinstance(function, ast.Lambda) else f'{function.name}()'


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
    if kind == 'command' and label in {'subprocess executable', 'os executable', 'interpreter source'}:
        # Shell quoting neither authorizes an executable nor escapes Python
        # source. Keep this distinction when substituting helper parameters.
        return False
    return kind in trace.sanitizers


def _literal_text(node):
    if isinstance(node, _LiteralString):
        return node.value
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _interpreter_kind(program):
    if program is None:
        return None
    leaf = program.replace('\\', '/').rsplit('/', 1)[-1].removesuffix('.exe')
    if leaf in {'sh', 'bash', 'dash', 'ash', 'zsh', 'ksh', 'mksh'}:
        return 'shell'
    if re.fullmatch(r'(?:python|pypy)(?:[0-9]+(?:\.[0-9]+)*)?[dt]?', leaf):
        return 'python'
    return None


def _interpreter_inputs(kind, arguments):
    """Return possible code operands, not data following a selected program.

    Arguments are already evaluated (AST expression, fact) snapshots. Unknown
    options/expansions retain the possibly executable suffix. A literal script,
    -c program, or -m module consumes option parsing: subsequent -c-looking data
    must not be reinterpreted as a second command. No analyzed code is executed.
    """
    index = 0
    shell_command = False
    while index < len(arguments):
        node, fact = arguments[index]
        option = _literal_text(node)
        if option is None:
            if shell_command and not isinstance(node, ast.Starred):
                return fact, CLEAN
            return CLEAN, join_facts(*(value for _node, value in arguments[index:]))
        if option == '--':
            value = arguments[index + 1][1] if index + 1 < len(arguments) else CLEAN
            return (value, CLEAN) if shell_command else (CLEAN, value)
        if option == '-' or not option.startswith(('-', '+')):
            # A dynamic script path is executable input; a fixed script path
            # is clean regardless of what follows in its application argv.
            return (fact, CLEAN) if shell_command else (CLEAN, fact)
        takes_value = ({'-o', '+o', '-O', '+O', '--rcfile', '--init-file'} if kind == 'shell'
                       else {'-W', '-X', '--check-hash-based-pycs'})
        if option in takes_value:
            index += 2
            continue
        if option.startswith('-') and not option.startswith('--'):
            if kind == 'python':
                for position, flag in enumerate(option[1:], 2):
                    if flag in {'c', 'm'}:
                        # The rest of this option is code/module text, not
                        # additional flags. -W/-X values must never supply c.
                        value = fact if option[position:] else (
                            arguments[index + 1][1] if index + 1 < len(arguments) else CLEAN)
                        return CLEAN, value
                    if flag in {'W', 'X'}:
                        if not option[position:]:
                            index += 1
                        break
            elif 'c' in option[1:]:
                shell_command = True
        index += 1
    return CLEAN, CLEAN


def _interpreter_reads_stdin(kind, arguments):
    """Whether stdin may be executable source, rather than application data."""
    index = 0
    shell_stdin = False
    while index < len(arguments):
        option = _literal_text(arguments[index][0])
        if option is None:
            return True
        if option == '--':
            return shell_stdin or index + 1 == len(arguments) or _literal_text(arguments[index + 1][0]) == '-'
        if option == '-':
            return True
        if not option.startswith(('-', '+')):
            return shell_stdin
        consumes = ({'-o', '+o', '-O', '+O', '--rcfile', '--init-file'} if kind == 'shell'
                    else {'-W', '-X', '--check-hash-based-pycs'})
        if option in consumes:
            index += 2
            continue
        if option.startswith('-') and not option.startswith('--'):
            if kind == 'shell':
                if 'c' in option[1:]:
                    return False
                shell_stdin = shell_stdin or 's' in option[1:]
            else:
                for position, flag in enumerate(option[1:], 2):
                    if flag in {'c', 'm'}:
                        return False
                    if flag in {'W', 'X'}:
                        if not option[position:]:
                            index += 1
                        break
        index += 1
    return True


class _State(dict):
    """Value facts, callable identities, and a field-insensitive object heap.

    Copying a variable copies references, not the object. Branches copy the
    heap map so writes on one branch cannot leak into an unrelated branch.
    """

    def __init__(self, values=(), bindings=None):
        super().__init__(values)
        self.bindings = dict(bindings if bindings is not None else getattr(values, 'bindings', {}))
        self.references = dict(getattr(values, 'references', {}))
        self.heap = dict(getattr(values, 'heap', {}))
        self.mutated = set(getattr(values, 'mutated', ()))
        self.reachable = getattr(values, 'reachable', True)

    def value(self, name):
        return join_facts(self.get(name, CLEAN), *(self.heap.get(ref, CLEAN)
                          for ref in self.references.get(name, NO_REFERENCES)))

    def copy(self):
        return _State(self)

    def replace(self, other):
        if other is None:
            self.reachable = False
            return
        self.clear()
        self.update(other)
        self.bindings = dict(other.bindings)
        self.references = dict(other.references)
        self.heap = dict(other.heap)
        self.mutated = set(other.mutated)
        self.reachable = other.reachable

    def __eq__(self, other):
        return (isinstance(other, _State) and dict.__eq__(self, other)
                and self.bindings == other.bindings and self.references == other.references
                and self.heap == other.heap and self.mutated == other.mutated
                and self.reachable == other.reachable)


def _join_states(*states):
    reachable = [state for state in states if state is not None and state.reachable]
    if not reachable:
        return None
    names = set().union(*(state.keys() for state in reachable))
    bindings = {}
    for name in set().union(*(state.bindings.keys() for state in reachable)):
        bindings[name] = _join_bindings(*(state.bindings.get(name, _implicit_identity(name)) for state in reachable))
    joined = _State({name: join_facts(*(state.get(name, CLEAN) for state in reachable)) for name in names}, bindings)
    for name in set().union(*(state.references for state in reachable)):
        joined.references[name] = frozenset().union(*(state.references.get(name, NO_REFERENCES) for state in reachable))
    for ref in set().union(*(state.heap for state in reachable)):
        joined.heap[ref] = join_facts(*(state.heap.get(ref, CLEAN) for state in reachable))
    joined.mutated = set().union(*(state.mutated for state in reachable))
    return joined


def _qualified(node: ast.AST, aliases: dict[str, object]) -> str:
    if isinstance(node, ast.Name):
        if node.id in aliases:
            target = aliases[node.id]
            if isinstance(target, str):
                return target
            if node.id in {'html', 'django', 'flask', 'markupsafe', 'bleach', 'shlex',
                           'subprocess', 'os', 'asyncio', 'builtins', 'eval', 'exec', 'input', 'raw_input',
                           'render_template', 'render_template_string', 'HttpResponse', 'Response'}:
                return ''
        return node.id
    if isinstance(node, ast.Attribute):
        base = _qualified(node.value, aliases)
        return _extend_qualifier(base, node.attr) if base else ''
    return ''


def _scope_nodes(scope):
    """Walk a lexical scope without reading the bodies of child scopes."""
    todo = [scope.body] if isinstance(scope, ast.Lambda) else list(reversed(scope.body))
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
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
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
class ExceptionSummary:
    exception_type: str | None
    value: Fact = CLEAN
    mutations: tuple = ()


@dataclass(frozen=True)
class FunctionSummary:
    returned: Fact = CLEAN
    # (kind, line, column, label, data). Symbolic parameters are substituted
    # at call sites; concrete request sources also stand alone in handlers.
    effects: tuple = ()
    # A generator's final return is StopIteration.value, not its yielded data.
    # Dependencies and ordinary iteration consume only the yielded values.
    yielded: Fact = CLEAN
    # A mutation is separate from a returned value or a sink effect: callers
    # can ignore the return and still observe writes through an output object.
    mutations: tuple = ()
    returned_references: frozenset[str] = frozenset()
    yielded_references: frozenset[str] = frozenset()
    returned_binding: object = frozenset()
    yielded_binding: object = frozenset()
    # Bottom means no normal continuation has been found yet. Recursion may
    # raise or have sink effects without ever returning to its caller.
    can_return: bool = False
    exceptions: tuple[ExceptionSummary, ...] = ()


@dataclass
class _Completion:
    """A pending exit, not yet committed to the function's summary.

    A finally suite may replace the exit. Value/callable identities are
    evaluated snapshots; an object still observes cleanup writes to its heap.
    """

    kind: str
    state: _State
    value: Fact = CLEAN
    references: References = NO_REFERENCES
    binding: object = None
    exception_type: str | None = None


def _merge_completions(completions):
    """Bound loop exit storage by completion kind and builtin exception type."""
    merged = {}
    for item in completions:
        key = (item.kind, item.exception_type)
        previous = merged.get(key)
        if previous is None:
            merged[key] = item
        else:
            merged[key] = _Completion(
                item.kind, _join_states(previous.state, item.state),
                join_facts(previous.value, item.value),
                previous.references | item.references,
                _join_bindings(previous.binding, item.binding), item.exception_type,
            )
    return list(merged.values())


class _Flow:
    def __init__(self, engine, scope):
        self.engine = engine
        self.scope = scope
        self.returned = CLEAN
        self.yielded = CLEAN
        self.effects = {}
        self.pending = []
        self.handled = []
        self.exception_states = []
        self.expression_facts = {}
        self.expression_bindings = {}
        self.generator_returns = {}
        self.generator_return_references = {}
        self.expression_references = {}
        self.mutations = {}
        self.returned_references = set()
        self.yielded_references = set()
        self.returned_bindings = []
        self.yielded_bindings = []
        self.generator_return_bindings = {}
        self.normal_state = None
        self.last_state = None

    def possible_exception(self, state):
        if state.reachable and self.exception_states:
            self.exception_states[-1] = _join_states(self.exception_states[-1], state)

    @staticmethod
    def exception_type(node, state):
        """Resolve only real, unshadowed builtin exception identities."""
        if isinstance(node, ast.Call):
            node = node.func
        name = _imported_name(node, state.bindings)
        if isinstance(node, ast.Name) and node.id not in state.bindings:
            name = node.id
        if name.startswith('@exception:'):
            name = name.removeprefix('@exception:')
        name = name.removeprefix('builtins.')
        value = getattr(builtins, name, None)
        return name if isinstance(value, type) and issubclass(value, BaseException) else None

    def handler_match(self, expression, raised, state):
        if expression is None:
            return True
        if isinstance(expression, ast.Tuple):
            matches = [self.handler_match(item, raised, state) for item in expression.elts]
            return True if True in matches else None if None in matches else False
        target = self.exception_type(expression, state)
        return self.exception_match(target, raised)

    @staticmethod
    def exception_match(target, raised):
        if target == 'BaseException':
            return True
        if target is None or raised is None:
            return None
        return issubclass(getattr(builtins, raised), getattr(builtins, target))

    def capture(self, statements, state, *, exceptions=False):
        """Analyze a suite without leaking its exits into an enclosing suite."""
        outer = self.pending
        self.pending = []
        if exceptions:
            self.exception_states.append(None)
        try:
            normal = self.block(statements, state)
            pending = self.pending
        finally:
            self.pending = outer
            exceptional = self.exception_states.pop() if exceptions else None
        if exceptional is not None:
            pending.append(_Completion('raise', exceptional))
        return normal, _merge_completions(pending)

    def try_statement(self, node, state):
        normal, pending = self.capture(node.body, state.copy(), exceptions=True)
        remaining = [item for item in pending if item.kind == 'raise']
        outgoing = [item for item in pending if item.kind != 'raise']
        # Else belongs exclusively to the normal try edge; its exceptions are
        # not candidates for any of this try statement's sibling handlers.
        normal, completed = self.capture(node.orelse, normal, exceptions=True)
        outgoing.extend(completed)
        normals = [normal]
        for handler in node.handlers:
            accepted, unmatched = [], []
            for item in remaining:
                match = self.handler_match(handler.type, item.exception_type, item.state)
                # Exception groups require subgroup splitting, not matching
                # the group's class against a leaf type. Keep all possibilities.
                if isinstance(node, getattr(ast, 'TryStar', ast.Try)) and not isinstance(node, ast.Try):
                    match = None
                if match is not False:
                    accepted.append(item)
                if match is not True:
                    unmatched.append(item)
            remaining = unmatched
            for item in accepted:
                branch = item.state.copy()
                self.expr(handler.type, branch)
                if handler.name:
                    branch[handler.name] = _advance(item.value, handler.name)
                    branch.references[handler.name] = item.references
                    branch.bindings[handler.name] = (
                        '@exception:' + item.exception_type if item.exception_type else None)
                self.handled.append(item)
                try:
                    end, exits = self.capture(handler.body, branch, exceptions=True)
                finally:
                    self.handled.pop()
                # Python deletes the `except ... as name` binding on every
                # exit. Saved aliases and already-evaluated returns survive.
                if handler.name:
                    for target in [end, *(exit_.state for exit_ in exits)]:
                        if target is not None:
                            target[handler.name] = CLEAN
                            target.bindings[handler.name] = None
                            target.references[handler.name] = NO_REFERENCES
                normals.append(end)
                outgoing.extend(exits)
        outgoing.extend(remaining)
        combined = _join_states(*normals)
        if not node.finalbody:
            self.pending.extend(_merge_completions(outgoing))
            return combined
        inputs = _merge_completions(outgoing)
        if combined is not None:
            inputs.append(_Completion('normal', combined))
        normals, outgoing = [], []
        for item in inputs:
            if item.kind == 'raise':
                self.handled.append(item)
            try:
                end, replacements = self.capture(node.finalbody, item.state.copy(), exceptions=True)
            finally:
                if item.kind == 'raise':
                    self.handled.pop()
            outgoing.extend(replacements)
            if end is not None:
                if item.kind == 'normal':
                    normals.append(end)
                else:
                    outgoing.append(_Completion(item.kind, end, item.value,
                                                item.references, item.binding, item.exception_type))
        self.pending.extend(_merge_completions(outgoing))
        return _join_states(*normals)

    def with_items(self, node, index, state):
        """Enter managers in order, unwinding only those already entered.

        A later context expression executes inside earlier managers. In
        particular, suppress() can handle its failure before the with-body
        starts, but it cannot handle failure of its own construction.
        """
        if index == len(node.items):
            return self.block(node.body, state)
        item = node.items[index]
        context = item.context_expr
        suppresses = (isinstance(context, ast.Call)
                      and _imported_name(context.func, state.bindings) == 'contextlib.suppress')
        types = tuple(self.exception_type(arg, state) for arg in context.args) if suppresses else None
        fact = self.expr(context, state)
        if not state.reachable:
            return None
        if item.optional_vars is not None:
            self.assign(item.optional_vars, fact, state)
        outer = self.pending
        self.pending = []
        self.exception_states.append(None)
        try:
            normal = self.with_items(node, index + 1, state)
            pending = self.pending
        finally:
            self.pending = outer
            exceptional = self.exception_states.pop()
        if exceptional is not None:
            pending.append(_Completion('raise', exceptional))
        normals, remaining = [normal], []
        for item in _merge_completions(pending):
            if item.kind != 'raise':
                remaining.append(item)
                continue
            matches = ([self.exception_match(type_, item.exception_type) for type_ in types]
                       if types is not None else [None])
            match = True if True in matches else None if None in matches else False
            if match is not False:
                normals.append(item.state)
            if match is not True:
                remaining.append(item)
        self.pending.extend(remaining)
        return _join_states(*normals)

    def mutate(self, references, fact, state):
        # Weak updates preserve other fields and possible aliases. A write of
        # clean data to one field is not proof that the whole object is safe.
        state.mutated.update(references)
        for ref in references:
            if fact:
                state.heap[ref] = join_facts(state.heap.get(ref, CLEAN), fact)
            self.mutations[ref] = join_facts(self.mutations.get(ref, CLEAN), fact)

    def effect(self, kind, node, label, fact):
        unsafe = frozenset(trace for trace in fact if not _safe_for(trace, kind, label))
        key = (kind, node.lineno, node.col_offset + 1, label)
        if unsafe:
            self.effects[key] = join_facts(self.effects.get(key, CLEAN), unsafe)

    def assign(self, target, fact, state, value=None, *, target_references=None):
        if isinstance(target, ast.Name):
            state[target.id] = _advance(fact, target.id)
            state.bindings[target.id] = self.expression_bindings.get(value)
            state.references[target.id] = self.expression_references.get(value, NO_REFERENCES)
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
            if target_references is None:
                self.expr(target.value, state)
                target_references = self.expression_references.get(target.value, NO_REFERENCES)
                # The receiver precedes an index that can rebind its name.
                if isinstance(target, ast.Subscript):
                    self.expr(target.slice, state)
            if target_references:
                self.mutate(target_references, fact, state)
                return
            base = target.value
            while isinstance(base, (ast.Subscript, ast.Attribute)):
                base = base.value
            if isinstance(base, ast.Name):
                references = state.references.get(base.id, NO_REFERENCES)
                if references:
                    self.mutate(references, _advance(fact, base.id), state)
                else:
                    state[base.id] = join_facts(state.get(base.id, CLEAN), _advance(fact, base.id))

    def source(self, node, state, candidate=None):
        # A supplied candidate was resolved before a call's argument effects.
        if candidate is not None:
            pass
        elif isinstance(node, ast.Call):
            candidate = _qualified(node.func, state.bindings) + '('
        elif isinstance(node, ast.Subscript):
            candidate = _qualified(node, state.bindings)
            base = _qualified(node.value, state.bindings)
            if base == 'params':
                candidate = 'params[...]'
            elif base == 'event' and isinstance(node.slice, ast.Constant) and node.slice.value == 'body':
                candidate = "event['body']"
        else:
            candidate = _qualified(node, state.bindings)
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
                references = self.engine.default_references.get(function, {}).get(name, NO_REFERENCES)
                bound[name] = join_facts(self.engine.defaults.get(function, {}).get(name, CLEAN),
                                         *(state.heap.get(ref, CLEAN) for ref in references))
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
            bound[f'@free:{name}'] = state.value(name)
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
                bound[f'@global:{name}'] = state.value(name)
        return bound

    def bind_references(self, function, node, keyword_nodes, state):
        """Bind references from evaluated argument snapshots, never re-read names.

        Variadic packs are new Python containers, not aliases to their values.
        Ordinary positional/keyword parameters and literal ** maps retain
        object identity. Unknown expansion is conservatively a may-alias set.
        """
        positional = [arg.arg for arg in (*function.args.posonlyargs, *function.args.args)]
        accepted = set(positional) | {arg.arg for arg in function.args.kwonlyargs}
        bound = {name: self.expression_references.get(arg, NO_REFERENCES)
                 for name, arg in zip(positional, node.args)}
        for name, expression in keyword_nodes.items():
            if name in accepted:
                bound[name] = self.expression_references.get(expression, NO_REFERENCES)
        for name, references in self.engine.default_references.get(function, {}).items():
            bound.setdefault(name, references)
        expanded = frozenset().union(*(self.expression_references.get(arg, NO_REFERENCES)
                                      for arg in node.args if isinstance(arg, ast.Starred)))
        if expanded:
            for name in positional:
                bound[name] = bound.get(name, NO_REFERENCES) | expanded
        for name in self.engine.closures.get(function, ()):
            bound[f'@free:{name}'] = state.references.get(name, NO_REFERENCES)
        for name in self.engine.global_names:
            if (not isinstance(self.scope, ast.Module)
                    and (name in self.engine.locals.get(self.scope, set())
                         or name in self.engine.closures.get(self.scope, set()))):
                bound[f'@global:{name}'] = frozenset({f'@global:{name}'})
            else:
                bound[f'@global:{name}'] = state.references.get(name, NO_REFERENCES)
        return bound

    def bind_values(self, function, node, keyword_nodes, state):
        positional = [arg.arg for arg in (*function.args.posonlyargs, *function.args.args)]
        bound = {name: self.expression_bindings.get(arg) for name, arg in zip(positional, node.args)}
        if any(isinstance(arg, ast.Starred) for arg in node.args):
            # Unknown expansion must not certify a particular program/option.
            bound.update((name, None) for name in positional)
        bound.update((name, self.expression_bindings.get(value)) for name, value in keyword_nodes.items()
                     if name is not None)
        for name, value in self.engine.default_bindings.get(function, {}).items():
            bound.setdefault(name, value)
        for name in self.engine.closures.get(function, ()):
            bound[f'@free:{name}'] = state.bindings.get(name)
        for name in self.engine.global_names:
            if (not isinstance(self.scope, ast.Module)
                    and (name in self.engine.locals.get(self.scope, set())
                         or name in self.engine.closures.get(self.scope, set()))):
                bound[f'@global:{name}'] = _SymbolicValue(f'@global:{name}')
            else:
                bound[f'@global:{name}'] = state.bindings.get(name)
        return bound

    def resume_environment(self, function, bound, references, values, state):
        """Arguments are captured at creation; globals and cells are read later.

        Refresh only the callee's real module namespace and cells owned by
        this lexical scope. A caller-local spelling is not a callee global,
        and an unrelated caller cannot replace a captured closure binding.
        """
        for name in self.engine.global_names:
            key = f'@global:{name}'
            shadowed = (not isinstance(self.scope, ast.Module)
                        and (name in self.engine.locals.get(self.scope, set())
                             or name in self.engine.closures.get(self.scope, set())))
            if shadowed:
                bound[key] = frozenset({TaintTrace(name, parameter=key, path=(name,))})
                references[key] = frozenset({key})
                values[key] = _SymbolicValue(key)
            else:
                bound[key] = state.value(name)
                references[key] = state.references.get(name, NO_REFERENCES)
                values[key] = state.bindings.get(name)
        for name in self.engine.closures.get(function, ()):
            owner = self.engine.enclosing(function)
            while owner is not None and not isinstance(owner, ast.Module):
                if name in self.engine.locals.get(owner, set()):
                    break
                owner = self.engine.enclosing(owner)
            if owner is self.scope:
                key = f'@free:{name}'
                bound[key] = state.value(name)
                references[key] = state.references.get(name, NO_REFERENCES)
                values[key] = state.bindings.get(name)

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

    def substitute_binding(self, binding, bound, references, node, call_name, values):
        choices = []
        for target in _binding_choices(binding):
            if isinstance(target, _SymbolicValue):
                choices.append(values.get(target.parameter))
            elif isinstance(target, _ArgumentVector):
                operands = []
                for operand, fact in target.operands:
                    if isinstance(operand, _SymbolicValue):
                        replacement = values.get(operand.parameter)
                        if isinstance(replacement, (_LiteralString, _SymbolicValue)):
                            operand = replacement
                    operands.append((operand, self.substitute(fact, bound, call_name)))
                choices.append(_ArgumentVector(tuple(operands)))
            elif isinstance(target, _BoundCallable):
                actual = frozenset().union(*(references.get(ref, NO_REFERENCES) if isinstance(ref, str)
                                             else frozenset({node}) for ref in target.references))
                choices.append(_BoundCallable(target.name, actual, self.substitute(target.receiver, bound, call_name)))
            elif isinstance(target, _DeferredCall):
                arguments = tuple((name, self.substitute(fact, bound, call_name))
                                  for name, fact in target.arguments)
                actual = tuple((name, frozenset().union(*(
                    references.get(ref, NO_REFERENCES) if isinstance(ref, str) else frozenset({node})
                    for ref in refs))) for name, refs in target.references)
                captured_values = tuple((name, self.substitute_binding(value, bound, references,
                                                                       node, call_name, values))
                                        for name, value in target.values)
                choices.append(_DeferredCall(target.function, target.call, arguments, actual, captured_values))
            else:
                choices.append(target)
        return _join_bindings(*choices)

    def command_operand(self, node, fact):
        literal = self.expression_bindings.get(node)
        if literal == 'sys.executable':
            literal = _LiteralString('python')
        return (literal if isinstance(literal, (_LiteralString, _SymbolicValue)) else node), fact

    def command_operands(self, node):
        """Expand literal argv without evaluating any argument a second time."""
        binding = self.expression_bindings.get(node)
        if isinstance(binding, _ArgumentVector):
            return list(binding.operands)
        if not isinstance(node, (ast.List, ast.Tuple)):
            return None
        result = []
        for item in node.elts:
            expanded = self.command_operands(item.value) if isinstance(item, ast.Starred) else None
            if expanded is not None:
                result.extend(expanded)
            else:
                result.append(self.command_operand(item, self.expression_facts.get(item, CLEAN)))
        return result

    def command_vectors(self, node):
        binding = self.expression_bindings.get(node)
        if isinstance(binding, (frozenset, _ArgumentVector)):
            return [list(value.operands) if isinstance(value, _ArgumentVector) else None
                    for value in _binding_choices(binding)]
        return [self.command_operands(node)]

    def interpreter_name(self, node):
        binding = self.expression_bindings.get(node)
        if binding == 'sys.executable':
            return 'python'
        return _literal_text(binding) or _literal_text(node)

    def process_input(self, node, program, operands, keyword_nodes, *, shell=False):
        """Remember only processes whose explicit stdin pipe accepts source.

        A communicate() spelling alone is not a process sink. The identity
        follows the process or its bound method, including local returns.
        """
        kind = _interpreter_kind(self.interpreter_name(program))
        pipe = keyword_nodes.get('stdin')
        piped = self.expression_bindings.get(pipe) == 'subprocess.PIPE' or (
            isinstance(pipe, ast.UnaryOp) and isinstance(pipe.op, ast.USub)
            and isinstance(pipe.operand, ast.Constant) and pipe.operand.value == 1)
        if not shell and piped and kind is not None and _interpreter_reads_stdin(kind, operands):
            return _ProcessInput(kind)
        return None

    def interpreter_effects(self, program_node, operands, stdin=CLEAN):
        program = self.interpreter_name(program_node)
        kind = _interpreter_kind(program)
        if kind is None:
            return CLEAN, CLEAN
        shell, raw = _interpreter_inputs(kind, operands)
        if stdin and _interpreter_reads_stdin(kind, operands):
            if kind == 'shell':
                shell = join_facts(shell, stdin)
            else:
                raw = join_facts(raw, stdin)
        return shell, raw

    def command_effect(self, node, executable, shell_code=CLEAN, interpreter_code=CLEAN):
        # One diagnostic at a process call even when more than one operand is
        # unsafe. Preserve the strict domain in symbolic helper summaries.
        if interpreter_code or executable:
            unsafe_shell = frozenset(trace for trace in shell_code
                                     if not _safe_for(trace, 'command', 'subprocess execution'))
            self.effect('command', node, 'interpreter source' if interpreter_code else 'subprocess executable',
                        join_facts(executable, interpreter_code, unsafe_shell))
        else:
            self.effect('command', node, 'subprocess execution', shell_code)

    def call(self, node, state):
        # Python evaluates the receiver/callable before argument expressions,
        # which may themselves reassign the receiver or callable name.
        self.expr(node.func, state)
        if not state.reachable:
            return CLEAN
        binding = self.expression_bindings.get(node.func)
        fallback_name = _qualified(node.func, state.bindings)
        receiver = (self.expression_facts.get(node.func.value, CLEAN)
                    if isinstance(node.func, ast.Attribute) else CLEAN)
        receiver_refs = (self.expression_references.get(node.func.value, NO_REFERENCES)
                         if isinstance(node.func, ast.Attribute) else NO_REFERENCES)
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
        if not state.reachable:
            return CLEAN
        # Scalars are snapshots, but passed objects observe mutations performed
        # while evaluating later arguments. Never re-evaluate the source AST.
        def live_argument(expression, fact):
            return join_facts(fact, *(state.heap.get(ref, CLEAN)
                              for ref in self.expression_references.get(expression, NO_REFERENCES)))
        arguments = [live_argument(expression, fact) for expression, fact in zip(node.args, arguments)]
        keywords = {key: live_argument(keyword_nodes.get(key), fact) for key, fact in keywords.items()}
        for expression in (*node.args, *keyword_nodes.values()):
            if self.expression_references.get(expression, NO_REFERENCES) & state.mutated:
                value = self.expression_bindings.get(expression)
                self.expression_bindings[expression] = _without_object_contract(value)
        branches, results, references, bindings = [], [], [], []
        # A join must retain possible dangerous callees. Each target sees the
        # same pre-call state; evaluating another target cannot sanitize it.
        for target in sorted(_binding_choices(binding), key=lambda value: (
                type(value).__name__, str(value) if isinstance(value, str) else '',
                getattr(value, 'lineno', 0), getattr(value, 'col_offset', 0))):
            branch = state.copy()
            self.expression_bindings.pop(node, None)
            self.expression_references.pop(node, None)
            result = self.invoke(node, branch, target, fallback_name, receiver,
                                 receiver_refs, arguments, keywords, keyword_nodes)
            if branch.reachable:
                results.append(result)
                references.append(self.expression_references.get(node, frozenset({node})))
                bindings.append(self.expression_bindings.get(node))
                branches.append(branch)
        state.replace(_join_states(*branches))
        self.expression_references[node] = frozenset().union(*references)
        self.expression_bindings[node] = _join_bindings(*bindings)
        return join_facts(*results)

    def invoke(self, node, state, target, fallback_name, receiver, receiver_refs,
               arguments, keywords, keyword_nodes, *, resumed=None):
        name = target if isinstance(target, str) else fallback_name if target is None else ''
        if isinstance(target, _BoundCallable):
            name = target.name
            receiver_refs = target.references
            receiver = join_facts(target.receiver, *(state.heap.get(ref, CLEAN) for ref in receiver_refs))
        if isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            function = target
            call_name = _call_name(function)
            if resumed is None:
                bound = self.bind(function, node, arguments, keywords, state)
                references = self.bind_references(function, node, keyword_nodes, state)
                values = self.bind_values(function, node, keyword_nodes, state)
            else:
                references = dict(resumed.references)
                values = dict(resumed.values)
                bound = {name: join_facts(fact, *(state.heap.get(ref, CLEAN)
                                              for ref in references.get(name, NO_REFERENCES)))
                         for name, fact in resumed.arguments}
                self.resume_environment(function, bound, references, values, state)
            if (isinstance(function, ast.AsyncFunctionDef)
                    and function not in self.engine.generators and resumed is None):
                self.expression_bindings[node] = _DeferredCall(
                    function, node, tuple(sorted(bound.items())), tuple(sorted(references.items())),
                    tuple(sorted(values.items())))
                self.expression_references[node] = NO_REFERENCES
                return CLEAN
            summary = self.engine.summaries.get(function, FunctionSummary())
            for kind, line, column, label, fact in summary.effects:
                propagated = self.substitute(fact, bound, call_name)
                propagated = frozenset(trace for trace in propagated if not _safe_for(trace, kind, label))
                key = (kind, line, column, label)
                if propagated:
                    self.effects[key] = join_facts(self.effects.get(key, CLEAN), propagated)
            for exception in summary.exceptions:
                exceptional = state.copy()
                for parameter, written in exception.mutations:
                    self.mutate(references.get(parameter, NO_REFERENCES),
                                self.substitute(written, bound, call_name), exceptional)
                self.pending.append(_Completion(
                    'raise', exceptional, self.substitute(exception.value, bound, call_name),
                    frozenset({node}),
                    '@exception:' + exception.exception_type if exception.exception_type else None,
                    exception.exception_type,
                ))
            if not summary.can_return and function not in self.engine.generators:
                state.reachable = False
                return CLEAN
            for parameter, written in summary.mutations:
                fact = self.substitute(written, bound, call_name)
                self.mutate(references.get(parameter, NO_REFERENCES), fact, state)
            returned_refs = frozenset().union(*(references.get(parameter, NO_REFERENCES)
                                               for parameter in summary.returned_references))
            self.expression_references[node] = returned_refs or frozenset({node})
            self.expression_bindings[node] = self.substitute_binding(
                summary.returned_binding, bound, references, node, call_name, values)
            returned = self.substitute(summary.returned, bound, call_name)
            if function in self.engine.generators:
                self.generator_returns[node] = returned
                self.generator_return_references[node] = returned_refs
                self.generator_return_bindings[node] = self.expression_bindings[node]
                self.expression_bindings[node] = self.substitute_binding(
                    summary.yielded_binding, bound, references, node, call_name, values)
                self.expression_references[node] = frozenset().union(*(
                    references.get(parameter, NO_REFERENCES) for parameter in summary.yielded_references))
                return self.substitute(summary.yielded, bound, call_name)
            return returned
        deferred = [target for expression in [*node.args, *keyword_nodes.values()]
                    for target in _binding_choices(self.expression_bindings.get(expression))
                    if isinstance(target, _DeferredCall)]
        awaitable = node.args[0] if node.args else keyword_nodes.get('main')
        alternatives = _binding_choices(self.expression_bindings.get(awaitable))
        if name == 'asyncio.run' and any(isinstance(item, _DeferredCall) for item in alternatives):
            # run() waits for completion; create_task()/gather() below do not.
            branches, values, returned_bindings, returned_refs = [], [], [], []
            for coroutine in alternatives:
                branch = state.copy()
                if isinstance(coroutine, _DeferredCall):
                    value = self.invoke(node, branch, coroutine.function, '', CLEAN, NO_REFERENCES,
                                        [], {}, {}, resumed=coroutine)
                    binding = self.expression_bindings.get(node)
                    refs = self.expression_references.get(node, NO_REFERENCES)
                else:
                    self.possible_exception(branch)
                    value = arguments[0] if arguments else keywords.get('main', CLEAN)
                    binding, refs = None, NO_REFERENCES
                if branch.reachable:
                    branches.append(branch)
                    values.append(value)
                    returned_bindings.append(binding)
                    returned_refs.append(refs)
            state.replace(_join_states(*branches))
            self.expression_bindings[node] = _join_bindings(*returned_bindings)
            self.expression_references[node] = frozenset().union(*returned_refs)
            return join_facts(*values)
        if deferred and (name in {'asyncio.create_task', 'asyncio.ensure_future', 'asyncio.gather'}
                         or name.endswith('.create_task')):
            self.expression_bindings[node] = _join_bindings(*deferred)
            for coroutine in deferred:
                # Scheduled tasks can run and mutate their arguments, but a
                # task failure is not a synchronous throw from create_task.
                branch = state.copy()
                outer = self.pending
                self.pending = []
                try:
                    self.invoke(node, branch, coroutine.function, '', CLEAN, NO_REFERENCES,
                                [], {}, {}, resumed=coroutine)
                    ends = [branch, *(item.state for item in self.pending)]
                finally:
                    self.pending = outer
                for end in ends:
                    for ref in end.heap.keys() | end.mutated:
                        self.mutate(frozenset({ref}), end.heap.get(ref, CLEAN), state)
            # Awaiting the returned task/gather group resolves these same
            # finite alternatives and observes any later argument mutations.
            self.expression_bindings[node] = _join_bindings(*deferred)
            self.expression_references[node] = NO_REFERENCES
        # Opaque external calls may return or raise. Known local calls instead
        # contribute exactly their summarized exceptional continuations above.
        # Builtin exception construction stores arguments; it is not an
        # arbitrary user call that could throw a different exception type.
        exception_constructor = self.exception_type(node.func, state) is not None
        if not exception_constructor:
            self.possible_exception(state)
        fact = join_facts(receiver, *arguments, *keywords.values(), self.source(node, state, name + '('))
        first = arguments[0] if arguments else CLEAN

        def source_argument(*names):
            if arguments:
                return first
            return join_facts(keywords.get(None, CLEAN), *(keywords.get(key, CLEAN) for key in names))

        leaf = name.rsplit('.', 1)[-1]
        mutators = {'append', 'add', 'insert', 'extend', 'update', 'setdefault', 'clear', 'pop',
                    'popitem', 'remove', 'reverse', 'sort', '__setitem__', '__delitem__', '__iadd__', '__imul__'}
        if receiver_refs and leaf in mutators:
            written = CLEAN
            if leaf in {'append', 'add'}:
                written = first
            elif leaf == 'insert':
                written = arguments[1] if len(arguments) > 1 else CLEAN
            elif leaf in {'extend', 'update', 'setdefault', '__iadd__'}:
                written = join_facts(*arguments, *keywords.values())
            elif leaf == '__setitem__':
                written = arguments[1] if len(arguments) > 1 else CLEAN
            self.mutate(receiver_refs, written, state)
        if leaf in {'render_template', 'render_template_string', 'HttpResponse', 'Response'}:
            label = 'render_template' if leaf.startswith('render_template') else ('Flask Response' if leaf == 'Response' else leaf)
            content = (join_facts(*arguments, *keywords.values()) if leaf.startswith('render_template')
                       else source_argument('content', 'response', 'body'))
            self.effect('xss', node, label, content)
        elif leaf in {'execute', 'executemany', 'text'} and name.split('.')[0] in {'cursor', 'session', 'conn', 'engine', 'db'}:
            query = source_argument('sql', 'query', 'statement', 'operation')
            self.effect('sql', node, 'SQL engine execute' if name.split('.')[0] in {'engine', 'db'} else 'SQL execute', query)
        elif name in {'subprocess.run', 'subprocess.Popen', 'subprocess.call', 'subprocess.check_output', 'subprocess.check_call'}:
            command_fact = source_argument('args')
            command_node = node.args[0] if node.args else keyword_nodes.get('args')
            shell = keyword_nodes.get('shell')
            shell_true = isinstance(shell, ast.Constant) and bool(shell.value)
            shell_unknown = (shell is not None and not isinstance(shell, ast.Constant)) or None in keywords
            explicit_executable = join_facts(keywords.get('executable', CLEAN), keywords.get(None, CLEAN))
            executable_node = keyword_nodes.get('executable')
            executable_literal = self.expression_bindings.get(executable_node)
            fixed_executable = (isinstance(executable_literal, _LiteralString)
                                or isinstance(executable_node, ast.Constant) and executable_node.value is not None)
            has_override = executable_node is not None and not (
                isinstance(executable_node, ast.Constant) and executable_node.value is None)
            executable, shell_code, interpreter_code = explicit_executable, CLEAN, CLEAN
            process_inputs = []
            stdin = keywords.get('input', CLEAN) if leaf in {'run', 'check_output'} else CLEAN
            # Keep each program/argv alternative paired. Combining the first
            # item of one branch with tainted data from another invents flows.
            for operands in self.command_vectors(command_node):
                command = (operands[0][1] if operands else CLEAN) if operands is not None else command_fact
                if (not shell_true or shell_unknown) and not fixed_executable:
                    executable = join_facts(executable, command)
                if shell_true or shell_unknown:
                    shell_code = join_facts(shell_code, command)
                    if has_override and _interpreter_kind(self.interpreter_name(executable_node)) != 'shell':
                        interpreter_code = join_facts(interpreter_code, command)
                process = None
                if not shell_true or shell_unknown:
                    program_node = executable_node if fixed_executable else operands[0][0] if operands else command_node
                    if operands is not None or self.interpreter_name(command_node) is not None:
                        tail = operands[1:] if operands else []
                        nested_shell, nested_raw = self.interpreter_effects(program_node, tail, stdin)
                        shell_code = join_facts(shell_code, nested_shell)
                        interpreter_code = join_facts(interpreter_code, nested_raw)
                        process = self.process_input(node, program_node, tail, keyword_nodes)
                    elif _interpreter_kind(self.interpreter_name(program_node)) is not None:
                        # A mutated/escaped vector no longer proves positional
                        # safety, even when executable= fixes argv[0].
                        interpreter_code = join_facts(interpreter_code, command_fact, stdin)
                process_inputs.append(process)
            if leaf == 'Popen':
                self.expression_bindings[node] = _join_bindings(*process_inputs)
            self.command_effect(node, executable, shell_code, interpreter_code)
        elif name == 'asyncio.create_subprocess_exec':
            executable = source_argument('program')
            program_node = node.args[0] if node.args else keyword_nodes.get('program')
            override = keyword_nodes.get('executable')
            if override is not None and not (isinstance(override, ast.Constant) and override.value is None):
                fixed = isinstance(self.expression_bindings.get(override), _LiteralString) or isinstance(override, ast.Constant)
                executable = join_facts(keywords.get('executable', CLEAN), CLEAN if fixed else executable)
                program_node = override
            operands = [self.command_operand(argument, value) for argument, value in zip(node.args[1:], arguments[1:])]
            shell_code, interpreter_code = self.interpreter_effects(program_node, operands)
            self.expression_bindings[node] = self.process_input(node, program_node, operands, keyword_nodes)
            self.command_effect(node, executable, shell_code, interpreter_code)
        elif name in {'os.execv', 'os.execve', 'os.execvp', 'os.execvpe', 'os.execl', 'os.execle',
                      'os.execlp', 'os.execlpe', 'os.posix_spawn', 'os.posix_spawnp'}:
            program_node = node.args[0] if node.args else keyword_nodes.get('path', keyword_nodes.get('file'))
            executable = source_argument('path', 'file')
            if leaf.startswith('execl'):
                tail = -1 if leaf.endswith('e') else len(node.args)
                operands = [self.command_operand(argument, value) for argument, value in zip(node.args[2:tail], arguments[2:tail])]
                shell_code, interpreter_code = self.interpreter_effects(program_node, operands)
            else:
                argv = node.args[1] if len(node.args) > 1 else keyword_nodes.get('argv', keyword_nodes.get('args'))
                shell_code, interpreter_code = CLEAN, CLEAN
                for vector in self.command_vectors(argv):
                    if vector is None and _interpreter_kind(self.interpreter_name(program_node)) is not None:
                        interpreter_code = join_facts(interpreter_code, self.expression_facts.get(argv, CLEAN))
                    else:
                        nested_shell, nested_raw = self.interpreter_effects(program_node, vector[1:] if vector else [])
                        shell_code = join_facts(shell_code, nested_shell)
                        interpreter_code = join_facts(interpreter_code, nested_raw)
            self.command_effect(node, executable, shell_code, interpreter_code)
        elif name in {'os.system', 'os.popen', 'subprocess.getoutput', 'subprocess.getstatusoutput',
                      'asyncio.create_subprocess_shell'}:
            command = source_argument('cmd', 'command')
            override = keyword_nodes.get('executable')
            has_override = override is not None and not (isinstance(override, ast.Constant) and override.value is None)
            program = _literal_text(self.expression_bindings.get(override)) or _literal_text(override)
            raw = command if has_override and _interpreter_kind(program) != 'shell' else CLEAN
            self.command_effect(node, keywords.get('executable', CLEAN), command, raw)
        elif name in {'eval', 'exec', 'builtins.eval', 'builtins.exec'}:
            self.effect('eval', node, leaf, source_argument('source', 'object'))
        elif name in {'@stdin.shell', '@stdin.python'}:
            code = source_argument('input')
            self.command_effect(node, CLEAN, code if name == '@stdin.shell' else CLEAN,
                                code if name == '@stdin.python' else CLEAN)
        else:
            # Passing a known vector to an unmodeled routine may mutate it.
            # Retain aggregate provenance but stop certifying its old shape.
            # This effect is summarized even for a symbolic helper parameter.
            for expression in (*node.args, *keyword_nodes.values()):
                value = self.expression_bindings.get(expression)
                if any(isinstance(choice, (_ArgumentVector, _SymbolicValue))
                       for choice in _binding_choices(value)) and name not in SANITIZERS and name not in {
                           'print', 'str', 'len', 'repr', 'tuple', 'list', 'bool', 'int', 'float',
                           'builtins.print', 'builtins.str', 'builtins.len', 'builtins.repr'}:
                    self.mutate(self.expression_references.get(expression, NO_REFERENCES), CLEAN, state)
        configurable_html = name == 'bleach.clean' and (
            len(node.args) > 1 or any(keyword.arg not in {'text', 'strip', 'strip_comments'} for keyword in node.keywords)
        )
        if name in SANITIZERS and not configurable_html:
            fact = _sanitize(fact, SANITIZERS[name])
        if not exception_constructor:
            self.possible_exception(state)
        return fact

    def expr(self, node, state):
        if not state.reachable:
            return CLEAN
        # Callable identity belongs to the point before its arguments execute:
        # Query(alias := other) still constructs the originally bound marker.
        imported_call = _imported_name(node.func, state.bindings) if isinstance(node, ast.Call) else ''
        exception_type = self.exception_type(node.func, state) if isinstance(node, ast.Call) else None
        may_raise = isinstance(node, (ast.Attribute, ast.Subscript,
                                      ast.BinOp, ast.Compare, ast.UnaryOp))
        if may_raise:
            self.possible_exception(state)
        self.expression_references.pop(node, None)
        self.expression_bindings.pop(node, None)
        fact = self.expression(node, state)
        if not state.reachable:
            return CLEAN
        if node is not None:
            self.expression_facts[node] = fact
            binding = self.expression_bindings.get(node)
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                binding = _LiteralString(node.value)
            elif isinstance(node, ast.Name):
                binding = state.bindings.get(node.id, _implicit_identity(node.id))
            elif isinstance(node, ast.Attribute):
                candidates = []
                receiver_refs = self.expression_references.get(node.value, NO_REFERENCES)
                receiver_fact = self.expression_facts.get(node.value, CLEAN)
                for base in _binding_choices(self.expression_bindings.get(node.value)):
                    if isinstance(base, _ProcessInput) and node.attr == 'communicate':
                        candidates.append(_BoundCallable('@stdin.' + base.kind, receiver_refs, receiver_fact))
                        continue
                    name = (_extend_qualifier(base, node.attr) if isinstance(base, str)
                            else _extend_qualifier(base.name, node.attr) if isinstance(base, _BoundCallable)
                            else _qualified(node, state.bindings))
                    framework = name.startswith('@fastapi.router.') or name in (
                        _PARAMETER_MARKERS | _DEPENDENCY_MARKERS | _ROUTER_TYPES | _REQUEST_TYPES | _SERVICE_TYPES)
                    candidates.append(_BoundCallable(name, receiver_refs, receiver_fact) if name and receiver_refs and not framework
                                      else name or None)
                binding = _join_bindings(*candidates)
                # A joined module identity can still denote a real source
                # (for example sys.argv), even when no single qualifier wins.
                for candidate in candidates:
                    name = candidate.name if isinstance(candidate, _BoundCallable) else candidate
                    if isinstance(name, str):
                        fact = join_facts(fact, self.source(node, state, name))
            elif isinstance(node, ast.Lambda):
                binding = node
            elif isinstance(node, ast.NamedExpr):
                binding = self.expression_bindings.get(node.value)
            elif isinstance(node, ast.IfExp):
                binding = _join_bindings(self.expression_bindings.get(node.body), self.expression_bindings.get(node.orelse))
            elif isinstance(node, ast.BoolOp):
                binding = _join_bindings(*(self.expression_bindings.get(value) for value in node.values))
            elif (isinstance(node, ast.Subscript) and isinstance(node.value, (ast.Tuple, ast.List))
                  and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int)
                  and -len(node.value.elts) <= node.slice.value < len(node.value.elts)):
                binding = self.expression_bindings.get(node.value.elts[node.slice.value])
            if isinstance(node, ast.Call):
                if exception_type:
                    binding = '@exception:' + exception_type
                if imported_call in _ROUTER_TYPES:
                    binding = '@fastapi.router'
                elif imported_call in _PARAMETER_MARKERS:
                    binding = _FrameworkInput('source', imported_call)
                elif imported_call in _DEPENDENCY_MARKERS:
                    binding = _FrameworkInput('dependency', imported_call,
                                              _dependency_target(node, state.bindings, self.expression_bindings))
            if isinstance(node, ast.Subscript):
                binding = _framework_input(node, state.bindings, evaluated=self.expression_bindings) or binding
            if isinstance(node, (ast.Tuple, ast.List)):
                markers = tuple(self.expression_bindings.get(item) for item in node.elts)
                if any(isinstance(marker, _FrameworkInput) for marker in markers):
                    binding = markers
                else:
                    binding = _ArgumentVector(tuple(self.command_operands(node)))
            self.expression_bindings[node] = binding
            if isinstance(node, ast.Name):
                self.expression_references[node] = state.references.get(node.id, NO_REFERENCES)
            elif isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
                self.expression_references[node] = self.expression_references.get(node.value, NO_REFERENCES)
            elif isinstance(node, ast.NamedExpr):
                self.expression_references[node] = self.expression_references.get(node.value, NO_REFERENCES)
            elif isinstance(node, (ast.List, ast.Tuple, ast.Dict, ast.Set, ast.Call)):
                self.expression_references.setdefault(node, frozenset({node}))
            if self.expression_references.get(node, NO_REFERENCES) & state.mutated:
                self.expression_bindings[node] = _without_object_contract(binding)
            self.expression_facts[node] = fact
        if may_raise:
            self.possible_exception(state)
        return fact

    def expression(self, node, state):
        if node is None or isinstance(node, ast.Constant):
            return CLEAN
        if isinstance(node, ast.Await):
            value = self.expr(node.value, state)
            if not state.reachable:
                return CLEAN
            branches, facts, bindings, references = [], [], [], []
            for target in _binding_choices(self.expression_bindings.get(node.value)):
                branch = state.copy()
                if isinstance(target, _DeferredCall):
                    fact = self.invoke(node, branch, target.function, '', CLEAN, NO_REFERENCES,
                                       [], {}, {}, resumed=target)
                    binding = self.expression_bindings.get(node)
                    refs = self.expression_references.get(node, NO_REFERENCES)
                else:
                    # Opaque awaitables may produce the value traced by the
                    # external source recognizer (e.g. Request.body()).
                    self.possible_exception(branch)
                    fact = value
                    # create_subprocess_* produces a process after awaiting;
                    # preserve its known stdin contract, not a coroutine's
                    # pre-resumption identity or an arbitrary unknown value.
                    binding = target if isinstance(target, _ProcessInput) else None
                    refs = self.expression_references.get(node.value, NO_REFERENCES)
                if branch.reachable:
                    branches.append(branch)
                    facts.append(fact)
                    bindings.append(binding)
                    references.append(refs)
            state.replace(_join_states(*branches))
            self.expression_bindings[node] = _join_bindings(*bindings)
            self.expression_references[node] = frozenset().union(*references)
            return join_facts(*facts)
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            self.yielded = join_facts(self.yielded, self.expr(node.value, state))
            self.yielded_references.update(self.expression_references.get(node.value, NO_REFERENCES))
            self.yielded_bindings.append(self.expression_bindings.get(node.value))
            if isinstance(node, ast.YieldFrom):
                self.expression_references[node] = self.generator_return_references.get(node.value, NO_REFERENCES)
                self.expression_bindings[node] = self.generator_return_bindings.get(node.value)
            # yield-from evaluates to the delegate's final return; an ordinary
            # yield expression instead receives a future send() value.
            return self.generator_returns.get(node.value, CLEAN) if isinstance(node, ast.YieldFrom) else CLEAN
        if isinstance(node, ast.Lambda):
            signature = node.args
            positional = [*signature.posonlyargs, *signature.args]
            defaults = {arg.arg: self.expr(value, state) for arg, value in
                        zip(positional[len(positional) - len(signature.defaults):], signature.defaults)}
            defaults.update({arg.arg: self.expr(value, state) for arg, value in
                             zip(signature.kwonlyargs, signature.kw_defaults) if value is not None})
            self.engine.defaults[node] = defaults
            self.engine.default_references[node] = {
                arg.arg: self.expression_references.get(value, NO_REFERENCES)
                for arg, value in (*zip(positional[len(positional) - len(signature.defaults):], signature.defaults),
                                   *zip(signature.kwonlyargs, signature.kw_defaults)) if value is not None
            }
            self.engine.default_bindings[node] = {
                arg.arg: self.expression_bindings.get(value)
                for arg, value in (*zip(positional[len(positional) - len(signature.defaults):], signature.defaults),
                                   *zip(signature.kwonlyargs, signature.kw_defaults)) if value is not None
            }
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
            return state.value(node.id)
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
            self.expression_references[node] = (self.expression_references.get(node.body, NO_REFERENCES)
                                                | self.expression_references.get(node.orelse, NO_REFERENCES))
            state.replace(_join_states(left, right))
            return fact
        if isinstance(node, ast.BoolOp):
            fact = CLEAN
            exits = []
            continuation = state.copy()
            for value in node.values:
                fact = join_facts(fact, self.expr(value, continuation))
                exits.append(continuation.copy())
            self.expression_references[node] = frozenset().union(*(self.expression_references.get(value, NO_REFERENCES)
                                                                   for value in node.values))
            state.replace(_join_states(*exits))
            return fact
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            # The outer iterable executes in the enclosing scope, even when
            # constructing a lazy generator. Inner iterations may be skipped.
            first = node.generators[0]
            iterable = self.expr(first.iter, state)
            if not state.reachable:
                return CLEAN
            nested = state.copy()
            for index, generator in enumerate(node.generators):
                value = iterable if index == 0 else self.expr(generator.iter, nested)
                self.assign(generator.target, value, nested)
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
            if state is None or not state.reachable:
                break
            self.last_state = state.copy()
            state = self.statement(node, state)
            if state is not None:
                self.last_state = state.copy()
        return state if state is not None and state.reachable else None

    def statement(self, node, state):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Decorator expressions run before defaults. Preserve the real
            # router identity even if a later default rebinds its name.
            route = False
            route_dependencies = []
            for decorator in node.decorator_list:
                is_route = isinstance(decorator, ast.Call) and _imported_name(decorator.func, state.bindings) in {
                    f'@fastapi.router.{method}' for method in _ROUTE_METHODS}
                route = route or is_route
                self.expr(decorator, state)
                if is_route:
                    markers = self.expression_bindings.get(_keyword_argument(decorator, 'dependencies'))
                    if isinstance(markers, tuple):
                        route_dependencies.extend(marker.dependency for marker in markers
                                                  if isinstance(marker, _FrameworkInput)
                                                  and marker.dependency is not None)
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
            self.engine.default_references[node] = {name: self.expression_references.get(default, NO_REFERENCES)
                                                    for name, default in defaults.items()}
            self.engine.default_bindings[node] = {name: self.expression_bindings.get(default) for name, default in defaults.items()}
            self.engine.describe_framework(node, default_inputs, state.bindings, route, route_dependencies)
            state[node.name] = CLEAN
            state.bindings[node.name] = node
            state.references[node.name] = NO_REFERENCES
        elif isinstance(node, ast.ClassDef):
            for expression in (*node.bases, *node.decorator_list):
                self.expr(expression, state)
            for keyword in node.keywords:
                self.expr(keyword.value, state)
            completed = self.block(node.body, state.copy())
            if completed is None:
                return None
            for ref, fact in completed.heap.items():
                state.heap[ref] = join_facts(state.heap.get(ref, CLEAN), fact)
            state[node.name] = CLEAN
            state.bindings[node.name] = node
            state.references[node.name] = NO_REFERENCES
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or alias.name.split('.')[0]
                state.bindings[local] = (f'{node.module}.{alias.name}' if isinstance(node, ast.ImportFrom)
                                         else alias.name if alias.asname else local)
                state[local] = CLEAN
                state.references[local] = NO_REFERENCES
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            if node.value is None:
                return state  # An annotation alone does not assign a value.
            fact = self.expr(node.value, state)
            if not state.reachable:
                return None
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                self.assign(target, fact, state, node.value)
        elif isinstance(node, ast.AugAssign):
            previous = self.expr(node.target, state)
            references = self.expression_references.get(node.target, NO_REFERENCES)
            fact = join_facts(previous, self.expr(node.value, state))
            self.assign(node.target, fact, state, target_references=references)
            # A known list += mutates the object observed by earlier aliases;
            # tuple/string += instead rebinds. Do not conflate these cases.
            if isinstance(node.target, ast.Name) and references and all(isinstance(ref, ast.List) for ref in references):
                self.mutate(references, fact, state)
                state.references[node.target.id] = references
        elif isinstance(node, ast.Assert):
            self.expr(node.test, state)
            if not state.reachable:
                return None
            if isinstance(node.test, ast.Constant) and node.test.value:
                return state
            # The message runs only on a raising path. Its sinks matter, but
            # its assignments cannot sanitize the normal continuation.
            failed = state.copy()
            value = self.expr(node.msg, failed)
            if failed.reachable:
                self.pending.append(_Completion('raise', failed, value, exception_type='AssertionError'))
            if isinstance(node.test, ast.Constant) and not node.test.value:
                return None
        elif isinstance(node, ast.Expr):
            self.expr(node.value, state)
        elif isinstance(node, ast.Return):
            value = self.expr(node.value, state)
            if not state.reachable:
                return None
            self.pending.append(_Completion('return', state.copy(), value,
                                            self.expression_references.get(node.value, NO_REFERENCES),
                                            self.expression_bindings.get(node.value)))
            return None
        elif isinstance(node, ast.Raise):
            exception_type = self.exception_type(node.exc, state)
            value = self.expr(node.exc, state)
            self.expr(node.cause, state)
            if not state.reachable:
                return None
            if node.exc is None and self.handled:
                previous = self.handled[-1]
                self.pending.append(_Completion('raise', state.copy(), previous.value,
                                                previous.references, previous.binding, previous.exception_type))
            else:
                self.pending.append(_Completion('raise', state.copy(), value,
                                                self.expression_references.get(node.exc, NO_REFERENCES),
                                                self.expression_bindings.get(node.exc), exception_type))
            return None
        elif isinstance(node, ast.If):
            self.expr(node.test, state)
            return _join_states(self.block(node.body, state.copy()), self.block(node.orelse, state.copy()))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            return self.loop(node, state)
        elif isinstance(node, ast.Break):
            self.pending.append(_Completion('break', state.copy()))
            return None
        elif isinstance(node, ast.Continue):
            self.pending.append(_Completion('continue', state.copy()))
            return None
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            return self.with_items(node, 0, state)
        elif isinstance(node, ast.Try) or (hasattr(ast, 'TryStar') and isinstance(node, ast.TryStar)):
            return self.try_statement(node, state)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    state[target.id] = CLEAN
                    state.bindings[target.id] = None
                    state.references[target.id] = NO_REFERENCES
                elif isinstance(target, (ast.Subscript, ast.Attribute)):
                    self.assign(target, CLEAN, state)
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
        return state if state.reachable else None

    def loop(self, node, state):
        is_while = isinstance(node, ast.While)
        always = bool(node.test.value) if is_while and isinstance(node.test, ast.Constant) else None
        # A for iterable is evaluated once, not on every worklist iteration.
        if not is_while:
            value = self.expr(node.iter, state)
            if not state.reachable:
                return None
            binding = self.expression_bindings.get(node.iter)
            references = self.expression_references.get(node.iter, NO_REFERENCES)
        head = state.copy()
        exits, outgoing = [], []
        while True:
            body = head.copy()
            if is_while:
                self.expr(node.test, body)
                condition_exit = body.copy() if always is not True else None
            else:
                condition_exit = head.copy()
                self.assign(node.target, value, body)
                # A local generator summary identifies its yielded callable;
                # an ordinary iterable object is not itself that callable.
                if isinstance(node.target, ast.Name) and node.iter in self.generator_returns:
                    body.bindings[node.target.id] = binding
                    body.references[node.target.id] = references
            back, pending = self.capture(node.body, None if always is False else body)
            exits = [_join_states(*exits, *(item.state for item in pending if item.kind == 'break'))]
            outgoing = _merge_completions([*outgoing, *(item for item in pending
                                                      if item.kind not in {'break', 'continue'})])
            joined = _join_states(state, back, *(item.state for item in pending if item.kind == 'continue'))
            if joined == head:
                break
            head = joined
        self.pending.extend(outgoing)
        normal = self.block(node.orelse, condition_exit)
        return _join_states(normal, *exits)

    def summary(self):
        returned = join_facts(self.returned, *(self.mutations.get(ref, CLEAN) for ref in self.returned_references))
        returned_references = set(self.returned_references)
        returned_bindings = list(self.returned_bindings)
        for item in self.pending:
            if item.kind == 'return':
                returned = join_facts(returned, item.value, *(item.state.heap.get(ref, CLEAN) for ref in item.references))
                returned_references.update(item.references)
                returned_bindings.append(item.binding)
        yielded = join_facts(self.yielded, *(self.mutations.get(ref, CLEAN) for ref in self.yielded_references))
        normal = _join_states(self.normal_state, *(item.state for item in self.pending if item.kind == 'return'))

        def mutations_on(state):
            # A clean write can replace a program or command flag. Preserve
            # invalidations even when they add no taint facts to the heap.
            return tuple(sorted((ref, state.heap.get(ref, CLEAN)) for ref in state.heap.keys() | state.mutated
                                if isinstance(ref, str)))

        mutations = mutations_on(normal) if normal is not None else ()
        exceptions = tuple(
            ExceptionSummary(item.exception_type,
                             join_facts(item.value, *(item.state.heap.get(ref, CLEAN) for ref in item.references)),
                             mutations_on(item.state))
            for item in _merge_completions(item for item in self.pending if item.kind == 'raise')
        )
        if self.normal_state is not None and not isinstance(self.scope, ast.Lambda):
            returned_bindings.append(None)  # Implicit `return None`.
        returned_binding = _join_bindings(*returned_bindings)
        yielded_binding = _join_bindings(*self.yielded_bindings)
        # finally may change an object after its return expression was read.
        # The object still returns, but its previous argv/process shape does
        # not. Keep this independent from whether the write added any taint.
        if returned_references & self.mutations.keys():
            returned_binding = _without_object_contract(returned_binding)
        if self.yielded_references & self.mutations.keys():
            yielded_binding = _without_object_contract(yielded_binding)
        return FunctionSummary(
            returned=returned, effects=tuple((*key, fact) for key, fact in sorted(self.effects.items())),
            yielded=yielded, mutations=mutations,
            returned_references=frozenset(ref for ref in returned_references if isinstance(ref, str)),
            yielded_references=frozenset(ref for ref in self.yielded_references if isinstance(ref, str)),
            returned_binding=returned_binding,
            yielded_binding=yielded_binding,
            can_return=normal is not None,
            exceptions=exceptions,
        )


class _Analysis:
    def __init__(self, tree):
        self.tree = tree
        self.summaries = {}
        self.defaults = {}
        self.framework_inputs = {}
        self.framework_dependencies = {}
        self.default_references = {}
        self.default_bindings = {}
        self.parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        self.functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))]
        self.generators = {function for function in self.functions
                           if any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in _scope_nodes(function))}
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
        while node is not None and not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            node = self.parents.get(node)
        return node

    def describe_framework(self, function, default_inputs, bindings, route, route_dependencies):
        inputs = {}
        for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
            description = (default_inputs.get(arg.arg)
                           or _framework_input(arg.annotation, bindings, annotation_strings=True))
            if description is None:
                description = _FrameworkInput('source' if route else 'implicit', 'fastapi.request')
            if description is not None:
                inputs[arg.arg] = description
        # Capture import identities at the definition, before later rebinding.
        self.framework_inputs[function] = inputs
        self.framework_dependencies[function] = tuple(route_dependencies)

    def framework_bound(self, globals_):
        """Solve local dependency values on the same finite taint lattice.

        Framework invocation is distinct from ordinary Python calls: provider
        parameters may be request inputs, but their callers receive only the
        provider's returned/yielded value, including its sanitizer domain.
        """
        providers = {description.dependency for inputs in self.framework_inputs.values()
                     for description in inputs.values() if description.dependency is not None}
        providers.update(provider for values in self.framework_dependencies.values() for provider in values)
        bound = {
            function: {name: frozenset({TaintTrace(description.name, path=(description.name, name))})
                       for name, description in inputs.items()
                       if description.kind == 'source' or (description.kind == 'implicit' and function in providers)}
            for function, inputs in self.framework_inputs.items()
        }
        global_bound = {f'@global:{name}': globals_.value(name) for name in globals_}
        while True:
            changed = False
            for function, inputs in self.framework_inputs.items():
                for name, description in inputs.items():
                    provider = description.dependency
                    if provider is None:
                        continue
                    summary = self.summaries.get(provider, FunctionSummary())
                    delivered = summary.yielded if provider in self.generators else summary.returned
                    incoming = _Flow.substitute(delivered, {**global_bound, **bound.get(provider, {})}, provider.name + '()')
                    previous = bound[function].get(name, CLEAN)
                    updated = join_facts(previous, incoming)
                    if updated != previous:
                        bound[function][name] = updated
                        changed = True
            if not changed:
                return bound

    def analyze(self):
        # A summary contains only finite source/parameter/sanitizer facts.
        # Equality excludes evidence paths, so recursive helpers terminate
        # without a depth cap that would silently lose longer call chains.
        while True:
            module = _Flow(self, self.tree)
            globals_ = module.block(self.tree.body, _State())
            if globals_ is None:
                # Keep definitions and global facts established before a
                # nonreturning call; they are still the callee's namespace.
                globals_ = module.last_state if module.last_state is not None else _State()
            changed = False
            flows = [module]
            for function in self.functions:
                local = self.locals[function]
                flow = _Flow(self, function)
                state = _State({name: frozenset({TaintTrace(name, parameter=f'@global:{name}', path=(name,))})
                                for name in self.global_names if name not in local},
                               {name: target for name, target in globals_.bindings.items() if name not in local})
                state.references.update({name: frozenset({f'@global:{name}'}) for name in self.global_names if name not in local})
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
                    else:
                        state.bindings[arg.arg] = _SymbolicValue(arg.arg)
                    state.references[arg.arg] = frozenset({arg.arg})
                for name in self.closures[function]:
                    state[name] = frozenset({TaintTrace(name, parameter=f'@free:{name}', path=(name,))})
                    state.bindings[name] = _SymbolicValue(f'@free:{name}')
                    state.references[name] = frozenset({f'@free:{name}'})
                if isinstance(function, ast.Lambda):
                    # Analyze lambda bodies once per fixed-point pass, not by
                    # recursively interpreting their call sites on our stack.
                    flow.exception_states.append(None)
                    flow.returned = flow.expr(function.body, state)
                    exceptional = flow.exception_states.pop()
                    if exceptional is not None:
                        flow.pending.append(_Completion('raise', exceptional))
                    flow.normal_state = state if state.reachable else None
                    flow.returned_references.update(flow.expression_references.get(function.body, NO_REFERENCES))
                    flow.returned_bindings.append(flow.expression_bindings.get(function.body))
                else:
                    if function.name not in local and function.name not in state.bindings:
                        state.bindings[function.name] = function
                    flow.normal_state, completed = flow.capture(function.body, state, exceptions=True)
                    flow.pending.extend(completed)
                summary = flow.summary()
                if summary != self.summaries.get(function, FunctionSummary()):
                    self.summaries[function] = summary
                    changed = True
                flows.append(flow)
            if not changed:
                effects = {}
                framework_bound = self.framework_bound(globals_)
                for flow in flows:
                    for key, fact in flow.effects.items():
                        if flow is not module:
                            bound = {f'@global:{name}': globals_.value(name) for name in globals_}
                            # Framework invocation is a separate entry point;
                            # summaries remain symbolic for ordinary callers.
                            bound.update(framework_bound.get(flow.scope, {}))
                            fact = flow.substitute(fact, bound, _call_name(flow.scope))
                        concrete = frozenset(trace for trace in fact if trace.parameter is None
                                             and not _safe_for(trace, key[0], key[3]))
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
