"""Function-scoped Python taint analysis with local call summaries (bead D6).

The AST transfer functions use strong assignment updates, join control-flow
branches, and iterate loops and recursive function summaries to a fixpoint.
Facts retain source provenance and sink-specific sanitizers. Local helpers
summarize both returned values and parameters reaching a sink; analyzed code
is never imported or executed. Selected Python modules share function
summaries, including qualified cycles with deferred peer lookups. Unresolved
imports, eager cyclic initialization and arbitrary dynamic dispatch retain
conservative opaque-call behavior. Known callable aliases are modeled.
Plain class-qualified static and unbound functions retain their callable
identity across selected modules and helper calls. Class namespace mutations
revoke those contracts; arbitrary descriptors and instance dispatch are opaque.
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
import operator
import os
import re
import sys
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Union

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
    arguments = _expanded_call(node).args
    argument = arguments[0] if arguments else _keyword_argument(node, 'dependency')
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
# A runtime alias, not an annotation: `ast.AST | str` would be evaluated and
# raise TypeError on Python 3.9, which ubs still supports (python_is_3).
References = frozenset[Union[ast.AST, str]]
NO_REFERENCES: References = frozenset()
_MISSING = object()  # absent-key sentinel for the state join


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


@dataclass(frozen=True)
class _ModuleBinding:
    project: object
    key: Path

    @property
    def reference(self):
        return '@module:' + str(self.key)

# Preserve the existing conventional unimported names, but never restore one
# after a local assignment/parameter has explicitly shadowed it.
_IMPLICIT_IDENTITIES = frozenset({
    'eval', 'exec', 'input', 'raw_input', 'print', 'str', 'builtins', 'staticmethod',
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
    if bindings and all(binding is bindings[0] for binding in bindings):
        only = bindings[0]
        if not isinstance(only, frozenset):
            return only
        return next(iter(only)) if len(only) == 1 else only
    choices = frozenset().union(*(_binding_choices(binding) for binding in bindings))
    if len(choices) == 1:
        return next(iter(choices))
    return choices  # Empty means no known return yet; None means unknown.


def _without_object_contract(binding):
    return _join_bindings(*(None if isinstance(value, (_ArgumentVector, _ProcessInput, ast.ClassDef)) else value
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


def _expanded_call(node):
    """Expose syntactic *list/*tuple arguments without evaluating them twice.

    The containers are fresh and cannot escape: unpacking them is equivalent
    to evaluating their elements in the same left-to-right argument order.
    Leave opaque unpackings intact, including their conservative may-alias
    behavior. Reuse this view for the lifetime of the analysis so call-site
    object identities stay finite through loop and summary fixed points.
    """
    arguments = []
    pending = list(reversed(node.args))
    while pending:
        argument = pending.pop()
        if isinstance(argument, ast.Starred) and isinstance(argument.value, (ast.List, ast.Tuple)):
            pending.extend(reversed(argument.value.elts))
        else:
            arguments.append(argument)
    if arguments == node.args:
        return node
    return ast.copy_location(ast.Call(func=node.func, args=arguments, keywords=node.keywords), node)


def join_facts(*facts: Fact) -> Fact:
    """Finite powerset join, retaining deterministic shortest evidence."""
    present = [fact for fact in facts if fact]
    if not present:
        return CLEAN
    head = present[0]
    # A lone fact, or one fact object joined with itself, is its own join:
    # its traces are already distinct. Returning it keeps object identity,
    # which lets repeated state joins take the identity fast path below.
    if type(head) is frozenset and all(fact is head for fact in present):  # ubs:ignore[py.comparison.type-equality,py.type-equality] - exact type on purpose: only a plain frozenset is known immutable with stock hashing/equality.
        return head
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
    # Exception edges join the whole state at every expression that may raise
    # inside a try suite, so this is the analyzer's hottest function. Values,
    # heap cells and references have a neutral element for a missing key and
    # an associative join, so they fold pairwise from a copy of the first
    # state; an entry that is the very same object on both sides (the common
    # case: most expressions change few names) is skipped without a join.
    first, others = reachable[0], reachable[1:]
    values = dict(first)
    heap = dict(first.heap)
    references = {key: frozenset(refs) for key, refs in first.references.items()}
    for other in others:
        for target, source in ((values, other), (heap, other.heap)):
            for key, fact in source.items():
                previous = target.get(key, _MISSING)
                if previous is _MISSING:
                    target[key] = fact
                elif previous is not fact:
                    target[key] = join_facts(previous, fact)
        for key, refs in other.references.items():
            previous = references.get(key, _MISSING)
            if previous is _MISSING:
                references[key] = frozenset(refs)
            elif previous is not refs:
                references[key] = previous | refs
    # A missing binding is not neutral: it stands for the name's implicit
    # identity, so bindings are joined over the full key union as before.
    bindings = {}
    if len(others) == 1:
        second = others[0].bindings
        for name, binding in first.bindings.items():
            other = second.get(name, _MISSING)
            if other is binding and not isinstance(binding, frozenset):
                bindings[name] = binding
            else:
                bindings[name] = _join_bindings(
                    binding, _implicit_identity(name) if other is _MISSING else other)
        for name, other in second.items():
            if name not in bindings:
                bindings[name] = _join_bindings(_implicit_identity(name), other)
    elif others:
        for name in set(first.bindings).union(*(state.bindings for state in others)):
            bindings[name] = _join_bindings(*(
                state.bindings[name] if name in state.bindings else _implicit_identity(name)
                for state in reachable))
    else:
        for name, binding in first.bindings.items():
            bindings[name] = _join_bindings(binding)
    joined = _State(values, bindings)
    joined.references = references
    joined.heap = heap
    joined.mutated = set(first.mutated).union(*(state.mutated for state in others))
    return joined


def _identity_snapshot(state):
    """The exact objects a state holds, for a join that would change nothing.

    The tuples keep every value alive, so identity comparison stays sound.
    """
    return (tuple(state), tuple(state.values()),
            tuple(state.bindings), tuple(state.bindings.values()),
            tuple(state.references), tuple(state.references.values()),
            tuple(state.heap), tuple(state.heap.values()),
            frozenset(state.mutated))


def _same_snapshot(left, right):
    # Keys compare by equality; values must be the very same objects, since
    # equal facts may still carry different (shorter) evidence paths.
    return (left[0] == right[0] and left[2] == right[2] and left[4] == right[4]
            and left[6] == right[6] and left[8] == right[8]
            and all(map(operator.is_, left[1], right[1]))
            and all(map(operator.is_, left[3], right[3]))
            and all(map(operator.is_, left[5], right[5]))
            and all(map(operator.is_, left[7], right[7])))


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


def _pattern_capture(node):
    """Pattern targets are strings in the AST, not Name(Store) nodes."""
    if hasattr(ast, 'MatchAs'):
        if isinstance(node, (ast.MatchAs, ast.MatchStar)):
            return node.name
        if isinstance(node, ast.MatchMapping):
            return node.rest
    return None


def _local_names(scope) -> set[str]:
    names = set()
    # Iteration targets belong to the comprehension, not its containing
    # function/module. Walrus targets still belong to the containing scope.
    comprehension_targets = {
        child for node in _scope_nodes(scope)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
        for generator in node.generators for child in ast.walk(generator.target)
    }
    for node in _scope_nodes(scope):
        if (isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
                and node not in comprehension_targets):
            names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
        elif (capture := _pattern_capture(node)) is not None:
            names.add(capture)
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


def _pattern_outcome(pattern, subject, binding):
    """Prove only irrefutable or literal matches; dynamic shapes stay unknown."""
    if _irrefutable_pattern(pattern):
        return True
    if isinstance(pattern, ast.MatchAs):
        return _pattern_outcome(pattern.pattern, subject, binding)
    if isinstance(pattern, ast.MatchOr):
        outcomes = [_pattern_outcome(part, subject, binding) for part in pattern.patterns]
        return True if True in outcomes else None if None in outcomes else False
    if isinstance(subject, ast.Constant):
        value = subject.value
    elif isinstance(binding, _LiteralString):
        value = binding.value
    else:
        return None
    if isinstance(pattern, ast.MatchSingleton):
        return value is pattern.value
    if isinstance(pattern, ast.MatchValue) and isinstance(pattern.value, ast.Constant):
        return value == pattern.value.value
    # AST constants cannot be mappings or matchable sequences (str/bytes
    # deliberately do not satisfy sequence patterns in Python).
    if isinstance(pattern, (ast.MatchMapping, ast.MatchSequence)):
        return False
    return None


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
        # Bound exact literal expansion across nested comprehensions. Once
        # exhausted, the finite-lattice loop still analyzes every possible
        # element/effect; this is a precision budget, not a scan cutoff.
        self.comprehension_budget = 64
        self.comprehension_environments = []

    def possible_exception(self, state):
        if not (state.reachable and self.exception_states):
            return
        # Most expressions leave the state untouched, and joining the same
        # state twice is idempotent: skip the join when this collector's last
        # joined state holds exactly the same objects. The collector is only
        # ever replaced, never mutated in place, so the snapshot recorded on
        # it stays true for as long as it is the collector.
        accumulated = self.exception_states[-1]
        snapshot = _identity_snapshot(state)
        previous = getattr(accumulated, 'last_joined', None)
        if previous is not None and _same_snapshot(previous, snapshot):
            return
        joined = _join_states(accumulated, state)
        joined.last_joined = snapshot
        self.exception_states[-1] = joined

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

    def condition(self, node, state):
        """Return truthy/falsy successors, preserving ordered guard effects."""
        if state is None or not state.reachable:
            return None, None
        if isinstance(node, ast.BoolOp):
            stopped = []
            continuation = state
            for operand in node.values:
                truthy, falsy = self.condition(operand, continuation)
                if isinstance(node.op, ast.And):
                    continuation = truthy
                    stopped.append(falsy)
                else:
                    continuation = falsy
                    stopped.append(truthy)
            return ((continuation, _join_states(*stopped)) if isinstance(node.op, ast.And)
                    else (_join_states(*stopped), continuation))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            truthy, falsy = self.condition(node.operand, state)
            return falsy, truthy
        if isinstance(node, ast.IfExp):
            left, right = self.condition(node.test, state)
            left_true, left_false = self.condition(node.body, left)
            right_true, right_false = self.condition(node.orelse, right)
            return _join_states(left_true, right_true), _join_states(left_false, right_false)
        self.expr(node, state)
        if not state.reachable:
            return None, None
        literal = node.value if isinstance(node, ast.NamedExpr) else node
        if isinstance(literal, ast.Constant):
            return (state, None) if bool(literal.value) else (None, state)
        binding = self.expression_bindings.get(node)
        if isinstance(binding, _LiteralString):
            return (state, None) if binding.value else (None, state)
        return state.copy(), state

    def bind_pattern(self, pattern, fact, state, binding=None, references=NO_REFERENCES):
        """Bind one successful pattern without executing the subject again.

        A whole-subject capture preserves callable identity and heap aliases.
        Extracted fields use the existing field-insensitive heap abstraction,
        but cannot inherit their container's callable/sanitizer identity. Star
        and mapping-rest captures allocate new containers, unlike AS aliases.
        """
        if isinstance(pattern, ast.MatchOr):
            alternatives = []
            for alternative in pattern.patterns:
                branch = state.copy()
                self.bind_pattern(alternative, fact, branch, binding, references)
                alternatives.append(branch)
            state.replace(_join_states(*alternatives))
            return
        if isinstance(pattern, ast.MatchAs):
            if pattern.pattern is not None:
                self.bind_pattern(pattern.pattern, fact, state, binding, references)
        elif isinstance(pattern, ast.MatchMapping):
            for child in pattern.patterns:
                self.bind_pattern(child, fact, state, references=references)
            binding, references = None, frozenset({pattern})
        elif isinstance(pattern, ast.MatchStar):
            binding, references = None, frozenset({pattern})
        elif isinstance(pattern, ast.MatchSequence):
            for child in pattern.patterns:
                self.bind_pattern(child, fact, state, references=references)
        elif isinstance(pattern, ast.MatchClass):
            for child in (*pattern.patterns, *pattern.kwd_patterns):
                self.bind_pattern(child, fact, state, references=references)
        name = _pattern_capture(pattern)
        if name is not None:
            state[name] = _advance(fact, name)
            state.bindings[name] = binding
            state.references[name] = references

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

    def closure_namespace(self, function, state):
        """Read cells in the callee's lexical scope, retaining the live heap.

        Comprehension targets shadow a caller's spelling, not the cells of
        an already defined helper. A lambda created inside a comprehension
        does capture that comprehension's cells, so preserve those frames.
        """
        ancestors = set()
        owner = self.engine.enclosing(function)
        while owner is not None:
            ancestors.add(owner)
            owner = self.engine.enclosing(owner)
        namespace = state
        for comprehension, outer in reversed(self.comprehension_environments):
            if comprehension in ancestors:
                continue
            if namespace is state:
                namespace = state.copy()
            for name in self.engine.locals[comprehension]:
                for destination, original in ((namespace, outer),
                                              (namespace.bindings, outer.bindings),
                                              (namespace.references, outer.references)):
                    if name in original:
                        destination[name] = original[name]
                    else:
                        destination.pop(name, None)
        return namespace

    def definition_table(self, table, function):
        """A callee's definition-time defaults, recorded as a job input."""
        value = getattr(self.engine, table).get(function)
        if self.engine.reads is not None:
            self.engine.reads[(table, function)] = value
        return value if value is not None else {}

    def global_arguments(self, function, state):
        """A helper reads its defining module, never a caller's same-name local."""
        owner = self.engine.owner(function)
        module_ref = (owner.project.module_reference(owner) if owner.project is not None else None)
        for name in owner.global_names:
            namespace = state if owner is self.engine else owner.globals
            if owner is self.engine:
                for comprehension, outer in self.comprehension_environments:
                    if name in self.engine.locals[comprehension]:
                        namespace = outer
                        break
            key = f'@global:{name}'
            if (owner is self.engine and not isinstance(self.scope, ast.Module)
                    and (name in self.engine.locals.get(self.scope, set())
                         or name in self.engine.closures.get(self.scope, set()))):
                yield key, frozenset({TaintTrace(name, parameter=key, path=(name,))}), frozenset({key}), _SymbolicValue(key)
            else:
                refs = namespace.references.get(name, NO_REFERENCES)
                fact = join_facts(namespace.value(name), state.heap.get(module_ref, CLEAN),
                                  *(state.heap.get(ref, CLEAN) for ref in refs))
                value = namespace.bindings.get(name)
                if refs & state.mutated or module_ref in state.mutated:
                    value = _without_object_contract(value)
                yield key, fact, refs, value

    def bind(self, function, node, arguments, keywords, state):
        positional = [arg.arg for arg in (*function.args.posonlyargs, *function.args.args)]
        bound = {name: fact for name, fact in zip(positional, arguments)}
        for name, fact in keywords.items():
            if name is not None:
                bound[name] = fact
        defaults = dict(zip(positional[-len(function.args.defaults):], function.args.defaults)) if function.args.defaults else {}
        defaults.update((arg.arg, default) for arg, default in zip(function.args.kwonlyargs, function.args.kw_defaults)
                        if default is not None)
        if defaults:
            default_facts = self.definition_table('defaults', function)
            default_references = self.definition_table('default_references', function)
        for name, default in defaults.items():
            if name not in bound:
                references = default_references.get(name, NO_REFERENCES)
                bound[name] = join_facts(default_facts.get(name, CLEAN),
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
        captured = self.closure_namespace(function, state)
        for name in self.engine.closures.get(function, ()):
            bound[f'@free:{name}'] = captured.value(name)
        for key, fact, _refs, _value in self.global_arguments(function, state):
            bound[key] = fact
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
        for name, references in self.definition_table('default_references', function).items():
            bound.setdefault(name, references)
        expanded = frozenset().union(*(self.expression_references.get(arg, NO_REFERENCES)
                                      for arg in node.args if isinstance(arg, ast.Starred)))
        if expanded:
            for name in positional:
                bound[name] = bound.get(name, NO_REFERENCES) | expanded
        captured = self.closure_namespace(function, state)
        for name in self.engine.closures.get(function, ()):
            bound[f'@free:{name}'] = captured.references.get(name, NO_REFERENCES)
        for key, _fact, refs, _value in self.global_arguments(function, state):
            bound[key] = refs
        if self.engine.project is not None:
            for key in self.engine.project.module_references:
                bound[key] = frozenset({key})
        return bound

    def bind_values(self, function, node, keyword_nodes, state):
        positional = [arg.arg for arg in (*function.args.posonlyargs, *function.args.args)]
        bound = {name: self.expression_bindings.get(arg) for name, arg in zip(positional, node.args)}
        if any(isinstance(arg, ast.Starred) for arg in node.args):
            # Unknown expansion must not certify a particular program/option.
            bound.update((name, None) for name in positional)
        bound.update((name, self.expression_bindings.get(value)) for name, value in keyword_nodes.items()
                     if name is not None)
        for name, value in self.definition_table('default_bindings', function).items():
            bound.setdefault(name, value)
        captured = self.closure_namespace(function, state)
        for name in self.engine.closures.get(function, ()):
            bound[f'@free:{name}'] = captured.bindings.get(name)
        for key, _fact, _refs, value in self.global_arguments(function, state):
            bound[key] = value
        return bound

    def resume_environment(self, function, bound, references, values, state):
        """Arguments are captured at creation; globals and cells are read later.

        Refresh only the callee's real module namespace and cells owned by
        this lexical scope. A caller-local spelling is not a callee global,
        and an unrelated caller cannot replace a captured closure binding.
        """
        for key, fact, refs, value in self.global_arguments(function, state):
            bound[key], references[key], values[key] = fact, refs, value
        captured = self.closure_namespace(function, state)
        for name in self.engine.closures.get(function, ()):
            owner = self.engine.enclosing(function)
            while owner is not None and not isinstance(owner, ast.Module):
                if name in self.engine.locals.get(owner, set()):
                    break
                owner = self.engine.enclosing(owner)
            if owner is self.scope or any(owner is scope for scope, _outer in self.comprehension_environments):
                key = f'@free:{name}'
                bound[key] = captured.value(name)
                references[key] = captured.references.get(name, NO_REFERENCES)
                values[key] = captured.bindings.get(name)

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
        original = node
        node = self.engine.call_sites.get(node, node)
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
        if original is not node:
            # Parent expressions, await/yield-from and for loops refer to the
            # source AST, not the normalized call-site view used for binding.
            for values in (self.expression_references, self.expression_bindings,
                           self.generator_returns, self.generator_return_references,
                           self.generator_return_bindings):
                if node in values:
                    values[original] = values[node]
                else:
                    values.pop(original, None)
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
            summary = self.engine.call_summary(function, values)
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
                if any(isinstance(choice, (_ArgumentVector, _SymbolicValue, ast.ClassDef))
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
                    if isinstance(base, ast.ClassDef):
                        members = self.engine.class_members.get(base, {})
                        if self.engine.reads is not None:
                            self.engine.reads[('class_members', base)] = members
                        candidates.append(members.get(node.attr))
                        continue
                    if isinstance(base, _ModuleBinding):
                        incoming, member, refs = base.project.member(base.key, node.attr, state)
                        fact = join_facts(fact, incoming)
                        self.expression_references[node] = self.expression_references.get(node, NO_REFERENCES) | refs
                        candidates.append(member)
                        continue
                    if isinstance(base, _ProcessInput) and node.attr == 'communicate':
                        candidates.append(_BoundCallable('@stdin.' + base.kind, receiver_refs, receiver_fact))
                        continue
                    name = (_extend_qualifier(base, node.attr) if isinstance(base, str)
                            else _extend_qualifier(base.name, node.attr) if isinstance(base, _BoundCallable)
                            else _qualified(node, state.bindings))
                    if not name and receiver_refs:
                        # A returned object has identity even without a source
                        # spelling (identity(box).append(...)). Keep the method
                        # and receiver without inventing an import/sanitizer.
                        name = _extend_qualifier('<object>', node.attr)
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
                self.expression_references.setdefault(node, self.expression_references.get(node.value, NO_REFERENCES))
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
            self.engine.define('defaults', node, defaults)
            self.engine.define('default_references', node, {
                arg.arg: self.expression_references.get(value, NO_REFERENCES)
                for arg, value in (*zip(positional[len(positional) - len(signature.defaults):], signature.defaults),
                                   *zip(signature.kwonlyargs, signature.kw_defaults)) if value is not None
            })
            self.engine.define('default_bindings', node, {
                arg.arg: self.expression_bindings.get(value)
                for arg, value in (*zip(positional[len(positional) - len(signature.defaults):], signature.defaults),
                                   *zip(signature.kwonlyargs, signature.kw_defaults)) if value is not None
            })
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
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
            return self.comprehension(node, state)
        if isinstance(node, ast.GeneratorExp):
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

    def comprehension(self, node, state):
        """Execute eager comprehension clauses in their implicit local scope.

        Heap writes and walrus assignments escape that scope on both normal
        and exceptional edges. Iteration targets do not. Filters are ordered
        branches, and mutable iterables participate in the loop fixed point.
        """
        first = node.generators[0]
        iterable = self.expr(first.iter, state)
        if not state.reachable:
            return CLEAN
        original = state.copy()
        local_names = self.engine.locals[node]
        nested = state.copy()
        for name in local_names:
            nested[name] = CLEAN
            nested.bindings[name] = None
            nested.references[name] = NO_REFERENCES
        result = CLEAN

        def project(current):
            if current is None:
                return None
            projected = current.copy()
            for target, source in ((projected, original),
                                   (projected.bindings, original.bindings),
                                   (projected.references, original.references)):
                for name in local_names:
                    if name in source:
                        target[name] = source[name]
                    else:
                        target.pop(name, None)
            return projected

        def clause(index, entering):
            nonlocal result
            if entering is None or not entering.reachable:
                return None
            generator = node.generators[index]
            value = iterable if index == 0 else self.expr(generator.iter, entering)
            if not entering.reachable:
                return None
            refs = self.expression_references.get(generator.iter, NO_REFERENCES)
            binding = self.expression_bindings.get(generator.iter)
            literal = generator.iter
            elements = None
            if (isinstance(literal, (ast.List, ast.Tuple))
                    and not any(isinstance(item, ast.Starred) for item in literal.elts)):
                elements = literal.elts
            elif isinstance(literal, ast.Dict) and all(key is not None for key in literal.keys):
                # Iterating a dictionary yields its keys, not its values.
                # Unknown/duplicate keys cannot establish an exact count.
                elements = literal.keys
            empty = (elements == [] or isinstance(literal, ast.Constant)
                     and isinstance(literal.value, (str, bytes)) and not literal.value)
            if empty:
                return entering

            def iteration(current, element=None):
                nonlocal result
                if current is None or not current.reachable:
                    return None
                if element is not None:
                    element_refs = self.expression_references.get(element, NO_REFERENCES)
                    fact = join_facts(self.expression_facts.get(element, CLEAN),
                                      *(current.heap.get(ref, CLEAN) for ref in element_refs))
                    self.assign(generator.target, fact, current, element)
                else:
                    fact = join_facts(value, *(current.heap.get(ref, CLEAN) for ref in refs))
                    self.assign(generator.target, fact, current)
                    if isinstance(generator.target, ast.Name):
                        if elements is not None:
                            current.bindings[generator.target.id] = _join_bindings(*(
                                self.expression_bindings.get(item) for item in elements))
                            current.references[generator.target.id] = frozenset().union(*(
                                self.expression_references.get(item, NO_REFERENCES) for item in elements))
                        elif generator.iter in self.generator_returns:
                            current.bindings[generator.target.id] = binding
                            current.references[generator.target.id] = refs
                for name in local_names:
                    if current.references.get(name, NO_REFERENCES) & current.mutated:
                        current.bindings[name] = _without_object_contract(current.bindings.get(name))
                skipped = []
                for condition in generator.ifs:
                    current, rejected = self.condition(condition, current)
                    skipped.append(rejected)
                if current is not None:
                    if index + 1 < len(node.generators):
                        current = clause(index + 1, current)
                    else:
                        values = ((node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,))
                        fact = join_facts(*(self.expr(item, current) for item in values))
                        if current.reachable:
                            result = join_facts(result, fact)
                return _join_states(current, *skipped)

            # Fresh sequence literals cannot acquire additional elements from
            # the body. Preserve evaluation order and element/callable aliases
            # without inventing a second iteration of a singleton sequence.
            if (elements is not None and isinstance(literal, (ast.List, ast.Tuple))
                    and len(elements) <= self.comprehension_budget):
                self.comprehension_budget -= len(elements)
                current = entering
                for element in elements:
                    current = iteration(current, element)
                return current
            if elements is not None:
                value = join_facts(*(self.expression_facts.get(item, CLEAN) for item in elements))
            head = entering.copy()
            exits = None if elements else entering.copy()
            while True:
                back = iteration(head.copy())
                exits = _join_states(exits, back)
                joined = _join_states(head, back)  # Ascending, as in loop().
                if joined == head:
                    return exits
                head = joined

        pending = self.pending
        self.pending = []
        collecting = bool(self.exception_states)
        if collecting:
            self.exception_states.append(None)
        self.comprehension_environments.append((node, original))
        try:
            normal = clause(0, nested)
            outgoing = self.pending
        finally:
            self.comprehension_environments.pop()
            self.pending = pending
            exceptional = self.exception_states.pop() if collecting else None
        self.pending.extend(_Completion(item.kind, project(item.state), item.value,
                                        item.references, item.binding, item.exception_type)
                            for item in _merge_completions(outgoing))
        if exceptional is not None:
            self.exception_states[-1] = _join_states(self.exception_states[-1], project(exceptional))
        state.replace(project(normal))
        self.expression_references[node] = frozenset({node})
        return result

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
            descriptors = []
            for decorator in node.decorator_list:
                is_route = isinstance(decorator, ast.Call) and _imported_name(decorator.func, state.bindings) in {
                    f'@fastapi.router.{method}' for method in _ROUTE_METHODS}
                route = route or is_route
                self.expr(decorator, state)
                descriptors.append(self.expression_bindings.get(decorator))
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
            self.engine.define('defaults', node, default_facts)
            self.engine.define('default_references', node, {
                name: self.expression_references.get(default, NO_REFERENCES) for name, default in defaults.items()})
            self.engine.define('default_bindings', node, {
                name: self.expression_bindings.get(default) for name, default in defaults.items()})
            self.engine.describe_framework(node, default_inputs, state.bindings, route, route_dependencies)
            self.engine.define('class_callables', node, not descriptors or descriptors in (
                ['staticmethod'], ['builtins.staticmethod']))
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
            members = {}
            if self.engine.plain_class(node, state):
                for name in _local_names(node):
                    value = completed.bindings.get(name)
                    if isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        value = value if self.engine.class_callables.get(value, False) else None
                    members[name] = value
            self.engine.define('class_members', node, members)
            state[node.name] = CLEAN
            state.bindings[node.name] = node
            state.references[node.name] = frozenset({node})
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or alias.name.split('.')[0]
                imported = (self.engine.project.imported(self.engine, node, alias, state)
                            if self.engine.project is not None else None)
                if imported is not None:
                    state[local], state.bindings[local], state.references[local] = imported
                    continue
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
            if not state.reachable:
                return None
            binding = self.expression_bindings.get(node.subject)
            references = self.expression_references.get(node.subject, NO_REFERENCES)
            branches = []
            remaining = state
            for case in node.cases:
                if remaining is None:
                    break
                outcome = _pattern_outcome(case.pattern, node.subject, binding)
                if outcome is False:
                    continue
                branch = remaining.copy()
                # The subject is evaluated once, but earlier guards may write
                # through its saved reference even after rebinding its name.
                fact = join_facts(subject, *(branch.heap.get(ref, CLEAN) for ref in references))
                current_binding = (_without_object_contract(binding) if references & branch.mutated else binding)
                self.bind_pattern(case.pattern, fact, branch, current_binding, references)
                # Failed partial-pattern bindings are unspecified by Python.
                # Retain both pre-pattern and possibly captured definitions,
                # without applying any guard effects to a failed pattern.
                unmatched = _join_states(remaining, branch) if outcome is None else None
                selected, rejected = ((branch, None) if case.guard is None
                                      else self.condition(case.guard, branch))
                branches.append(self.block(case.body, selected))
                remaining = _join_states(unmatched, rejected)
            return _join_states(*branches, remaining)
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
                # The iterator keeps the original object, not the current
                # binding of its expression. Writes through any alias on a
                # back edge can expose new elements on a later iteration.
                # Read its heap at the fixed point, but keep each scalar
                # element a snapshot (not an alias of the iterable itself).
                current_value = join_facts(value, *(body.heap.get(ref, CLEAN) for ref in references))
                self.assign(node.target, current_value, body)
                # A local generator summary identifies its yielded callable;
                # an ordinary iterable object is not itself that callable.
                if isinstance(node.target, ast.Name) and node.iter in self.generator_returns:
                    body.bindings[node.target.id] = binding
                    body.references[node.target.id] = references
            back, pending = self.capture(node.body, None if always is False else body)
            exits = [_join_states(*exits, *(item.state for item in pending if item.kind == 'break'))]
            outgoing = _merge_completions([*outgoing, *(item for item in pending
                                                      if item.kind not in {'break', 'continue'})])
            # Accumulate into the head rather than recomputing entry ⊔ back:
            # for a monotone body the two sequences are the same, and when a
            # transfer is not monotone (a guard that reads a callable choice,
            # say) the head can no longer oscillate between two states. A
            # real pptx loop nest did exactly that for thousands of rounds.
            joined = _join_states(head, back, *(item.state for item in pending if item.kind == 'continue'))
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
    def __init__(self, tree, project=None):
        self.tree = tree
        self.project = project
        self.globals = _State()
        self.summaries = {}
        self.defaults = {}
        self.framework_inputs = {}
        self.framework_values = {}
        self.framework_dependencies = {}
        # While a job is solved: every summary and definition-time table
        # entry it reads, so an unchanged job is not solved again.
        self.reads = None
        self.writes = None
        self.default_references = {}
        self.default_bindings = {}
        self.class_members = {}
        self.class_callables = {}
        self.parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        self.call_sites = {node: _expanded_call(node) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        self.functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))]
        self.generators = {function for function in self.functions
                           if any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in _scope_nodes(function))}
        self.locals = {scope: _local_names(scope) for scope in [tree, *self.functions]}
        for node in ast.walk(tree):
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                self.locals[node] = {child.id for generator in node.generators
                                    for child in ast.walk(generator.target)
                                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)}
        self.global_names = self.locals[tree]
        self.closures = {}
        for function in self.functions:
            available = set()
            parent = self.enclosing(function)
            while parent is not None and not isinstance(parent, ast.Module):
                available.update(self.locals.get(parent, set()))
                parent = self.enclosing(parent)
            self.closures[function] = available - self.locals[function]

    def owner(self, function):
        return self.project.owners.get(function, self) if self.project is not None else self

    @staticmethod
    def plain_class(node, state):
        """Prove the bounded class namespace used for class-qualified calls.

        There is no instance/descriptor or inheritance simulation here. Only
        a class using the default metaclass and straight-line declarations
        can supply members. Executable namespace construction remains opaque.
        Definitions still run through the ordinary transfer functions, which
        capture actual decorator bindings and definition-time defaults.
        """
        if node.bases or node.keywords or node.decorator_list:
            return False

        def literal(value):
            return value is None or all(isinstance(child, (
                ast.Constant, ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Load,
                ast.UnaryOp, ast.UAdd, ast.USub,
            )) for child in ast.walk(value))

        def annotation(value):
            if value is None:
                return True
            for child in ast.walk(value):
                if isinstance(child, ast.Name):
                    if child.id not in {'str', 'bytes', 'int', 'float', 'bool', 'object',
                                         'list', 'tuple', 'dict', 'set', 'frozenset', 'type'}:
                        return False
                    if child.id in state.bindings:
                        return False
                elif not isinstance(child, (ast.Constant, ast.Load, ast.Subscript,
                                            ast.Tuple, ast.BinOp, ast.BitOr)):
                    return False
            return True

        for statement in node.body:
            if isinstance(statement, ast.Pass):
                continue
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                continue
            if isinstance(statement, ast.Assign):
                if all(isinstance(target, ast.Name) for target in statement.targets) and literal(statement.value):
                    continue
            elif isinstance(statement, ast.AnnAssign):
                if (isinstance(statement.target, ast.Name) and literal(statement.value)
                        and annotation(statement.annotation)):
                    continue
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = statement.args
                params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
                params.extend(arg for arg in (args.vararg, args.kwarg) if arg is not None)
                if (not getattr(statement, 'type_params', ())
                        and all(literal(value) for value in (*args.defaults, *args.kw_defaults))
                        and annotation(statement.returns)
                        and all(annotation(arg.annotation) for arg in params)):
                    continue
            return False
        return True

    def enclosing(self, node):
        child = node
        parent = self.parents.get(child)
        in_iterable = False
        while parent is not None:
            if isinstance(parent, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                return parent
            if (isinstance(parent, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
                    and not (child is parent.generators[0] and in_iterable)):
                return parent
            if isinstance(parent, ast.comprehension):
                in_iterable = child is parent.iter
            child, parent = parent, self.parents.get(parent)
        return None

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
        self.define('framework_inputs', function, inputs)
        self.define('framework_dependencies', function, tuple(route_dependencies))

    def define(self, table, node, value):
        """Record a definition-time table entry; a reused job replays it."""
        getattr(self, table)[node] = value
        if self.writes is not None:
            self.writes.append((table, node, value))

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
                    owner = self.owner(provider)
                    provider_globals = (global_bound if owner is self else
                                        {f'@global:{key}': owner.globals.value(key) for key in owner.globals})
                    provider_inputs = bound.get(provider, {}) if owner is self else owner.framework_values.get(provider, {})
                    incoming = _Flow.substitute(delivered, {**provider_globals, **provider_inputs}, provider.name + '()')
                    previous = bound[function].get(name, CLEAN)
                    updated = join_facts(previous, incoming)
                    if updated != previous:
                        bound[function][name] = updated
                        changed = True
            if not changed:
                return bound

    def call_summary(self, function, values):
        """Request a symbolic summary for known callback identities.

        Facts, heaps and evidence paths are NOT context keys. Only finite
        source-level callable identities distinguish invocations; unresolved
        alternatives stay opaque rather than certifying a sanitizer. A new
        context starts at bottom and is solved by the normal fixed-point
        loop, never by recursively interpreting callees on the Python stack.
        """
        context = []
        for name, binding in sorted(values.items()):
            if name.startswith('@global:'):
                # A class namespace is a mutable object. A caller may replace
                # one of its methods after a helper's definition, so neither
                # the helper's original nor the module's final class binding
                # can certify this invocation. Include the finite class value
                # (or its revoked/unknown alternative) in the summary context.
                nominal = self.owner(function).globals.bindings.get(name[len('@global:'):])
                if not any(isinstance(value, ast.ClassDef)
                           for value in (*_binding_choices(binding), *_binding_choices(nominal))):
                    continue
            choices = frozenset(value if isinstance(value, (str, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef))
                                else None for value in _binding_choices(binding))
            if name.startswith('@global:') or any(value is not None for value in choices):
                context.append((name, _join_bindings(*choices)))
        key = (function, tuple(context)) if context else function
        summary = self.summaries.setdefault(key, FunctionSummary())
        if self.reads is not None:
            self.reads[('summaries', key)] = summary
        return summary

    def reads_current(self, reads):
        """Did every input a job read keep its value? Summaries by identity."""
        for (table, key), value in reads.items():
            current = getattr(self, table).get(key)
            stale = (current is not value) if table == 'summaries' else (current != value)
            if stale:
                return False
        return True

    def analyze(self):
        # A summary contains only finite source/parameter/sanitizer facts.
        # Equality excludes evidence paths, so recursive helpers terminate
        # without a depth cap that would silently lose longer call chains.
        #
        # Project analysis shares one summary table. A callback context that
        # an earlier module requested for a foreign function was solved to
        # its fixed point before that module became ready: its owner's
        # namespace is final and its key fixes the callable identities, so
        # nothing this module does can change it. Re-solving every inherited
        # context on every pass of every later module made project scans
        # quadratic in the module count; only contexts this module requests,
        # or that belong to its own functions, are part of its fixed point.
        solving = self.project.solving if self.project is not None else set()
        inherited = {key for key in self.summaries
                     if isinstance(key, tuple) and self.owner(key[0]) is not self
                     and self.owner(key[0]) not in solving}
        # Worklist: a job is a deterministic function of its namespace, the
        # summaries it requested and the definition-time tables it read. When
        # none of those changed since its last solve, solving it again yields
        # the same summary and the same flow, so the previous ones are reused.
        solved = {}  # summary key -> (reads, writes, flow) of the job's last solve
        while True:
            previous_contexts = len(self.summaries)
            module = _Flow(self, self.tree)
            globals_ = module.block(self.tree.body, _State())
            if globals_ is None:
                # Keep definitions and global facts established before a
                # nonreturning call; they are still the callee's namespace.
                globals_ = module.last_state if module.last_state is not None else _State()
            # Imported higher-order helpers may call a callback defined by
            # this module. Publish this pass's namespace before solving those
            # contexts, and iterate again when initialization facts change.
            changed = globals_ != self.globals
            if changed:
                solved.clear()  # Every job of this module starts from the namespace.
            self.globals = globals_
            flows = [module]
            jobs = [(function, (), function) for function in self.functions]
            jobs.extend((key[0], key[1], key) for key in list(self.summaries)
                        if isinstance(key, tuple) and key not in inherited)
            for function, context, summary_key in jobs:
                owner = self.owner(function)
                previous = solved.get(summary_key)
                if previous is not None and owner.reads_current(previous[0]):
                    # Replay its definition-time writes, in job order, so later
                    # jobs read exactly what a fresh solve would have left.
                    for table, node, value in previous[1]:
                        getattr(owner, table)[node] = value
                    if not context:
                        flows.append(previous[2])
                    continue
                reads = {('framework_inputs', function): owner.framework_inputs.get(function)}
                writes = []
                owner.reads, owner.writes = reads, writes
                namespace = globals_ if owner is self else owner.globals
                local = owner.locals[function]
                flow = _Flow(owner, function)
                state = _State({name: frozenset({TaintTrace(name, parameter=f'@global:{name}', path=(name,))})
                                for name in owner.global_names if name not in local},
                               {name: target for name, target in namespace.bindings.items() if name not in local})
                state.references.update({name: frozenset({f'@global:{name}'}) for name in owner.global_names if name not in local})
                for name in local:
                    state.bindings[name] = None
                arguments = function.args
                params = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
                params.extend(arg for arg in (arguments.vararg, arguments.kwarg) if arg is not None)
                for arg in params:
                    state[arg.arg] = frozenset({TaintTrace(arg.arg, parameter=arg.arg, path=(arg.arg,))})
                    description = owner.framework_inputs.get(function, {}).get(arg.arg)
                    if description is not None and description.kind == 'request':
                        state.bindings[arg.arg] = '@request:' + description.name
                    else:
                        state.bindings[arg.arg] = _SymbolicValue(arg.arg)
                    state.references[arg.arg] = frozenset({arg.arg})
                for name in owner.closures[function]:
                    state[name] = frozenset({TaintTrace(name, parameter=f'@free:{name}', path=(name,))})
                    state.bindings[name] = _SymbolicValue(f'@free:{name}')
                    state.references[name] = frozenset({f'@free:{name}'})
                for name, binding in context:
                    state.bindings[name.removeprefix('@free:').removeprefix('@global:')] = binding
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
                owner.reads = owner.writes = None
                solved[summary_key] = (reads, writes, flow)
                if summary != self.summaries.get(summary_key, FunctionSummary()):
                    self.summaries[summary_key] = summary
                    changed = True
                # Contextual effects belong to their calling invocation, not
                # an invented standalone/framework entry into a foreign scope.
                if not context:
                    flows.append(flow)
            if not changed and len(self.summaries) == previous_contexts:
                self.globals = globals_
                effects = {}
                framework_bound = self.framework_bound(globals_)
                self.framework_values = framework_bound
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


class _Project:
    """Resolve only selected Python source files; never search sys.path/import code.

    Module initialization is dependency ordered. A cyclic component with only
    literal initialization and deferred peer lookups can share a fixed point.
    Other cycles keep opaque imports, not a guessed partial namespace; their
    dependents still resolve selected-module summaries normally.
    A virtual line map keeps imported sink locations and suppressions attached
    to their defining file without concatenating/parsing source buffers.
    """

    def __init__(self, files, root=None):
        self.sources = []
        self.modules = {}
        self.namespaces = set()
        self.keys = {}
        self.ready = set()
        self.solving = set()
        seen, offset = set(), 0
        for path in files:
            path = Path(path).resolve()
            # The caller selected these files (iter_files or runner discovery);
            # re-applying SKIP_DIRS to the absolute path dropped every file
            # under an ancestor named build/, dist/, ... (GH #151).
            if path in seen or path.suffix.lower() not in EXTS:
                continue
            seen.add(path)
            try:
                text = path.read_text(encoding='utf-8')
                tree = ast.parse(text, filename=str(path))
            except (OSError, UnicodeError, SyntaxError, ValueError):
                continue
            ast.increment_lineno(tree, offset)
            engine = _Analysis(tree, self)
            self.sources.append((path, text, engine, offset))
            if path.suffix == '.py':
                key = path.parent if path.name == '__init__.py' else path.with_suffix('')
                self.keys[engine] = key
                # foo.py and foo/__init__.py cannot both prove a module identity.
                self.modules[key] = None if key in self.modules else engine
            offset += max(1, len(text.splitlines()) + 1)
        parents = [str(path.parent) for path, _, _, _ in self.sources]
        self.root = Path(root).resolve() if root else Path(os.path.commonpath(parents)) if parents else Path.cwd()
        if self.root.is_file():
            self.root = self.root.parent
        for key in self.modules:
            self.namespaces.add(key)
            self.namespaces.update(parent for parent in key.parents if parent.is_relative_to(self.root))
        self.owners = {function: engine for _, _, engine, _ in self.sources for function in engine.functions}
        self.module_references = {'@module:' + str(key) for key in self.namespaces}
        # AST-keyed metadata is safe to share. Module variable namespaces and
        # framework entrypoint bindings remain separate per defining module.
        for name in ('summaries', 'defaults', 'default_references', 'default_bindings', 'parents', 'locals', 'closures',
                     'class_members', 'class_callables'):
            shared = {}
            for _, _, engine, _ in self.sources:
                shared.update(getattr(engine, name))
            for _, _, engine, _ in self.sources:
                setattr(engine, name, shared)
        generators = set().union(*(engine.generators for _, _, engine, _ in self.sources))
        for _, _, engine, _ in self.sources:
            engine.generators = generators

    def module_reference(self, engine):
        key = self.keys.get(engine)
        return '@module:' + str(key) if key is not None else None

    def import_key(self, engine, node, name):
        if isinstance(node, ast.ImportFrom) and node.level:
            key = self.keys.get(engine)
            if key is None:
                return None
            path = next(path for path, _, candidate, _ in self.sources if candidate is engine)
            base = path.parent
            for _ in range(node.level - 1):
                base = base.parent
            if not base.is_relative_to(self.root):
                return None
        else:
            base = self.root
        return base.joinpath(*name.split('.')) if name else base

    def dependencies(self, engine):
        dependencies = set()
        for node in ast.walk(engine.tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            names = ([node.module or '', *('.'.join(filter(None, (node.module, alias.name)))
                      for alias in node.names if alias.name != '*')]
                     if isinstance(node, ast.ImportFrom) else [alias.name for alias in node.names])
            for name in names:
                key = self.import_key(engine, node, name)
                if key is None:
                    continue
                for prefix in (key, *key.parents):
                    dependency = self.modules.get(prefix)
                    if dependency is not None and (dependency is not engine or prefix == key):
                        dependencies.add(dependency)
        return dependencies

    def components(self):
        """Yield strongly connected import components, dependencies first.

        An iterative Tarjan walk bounds stack use by the selected graph, not
        Python's recursion limit. Only a genuine cycle needs the opaque-import
        fallback: a module importing a cycle may also call independent helpers
        whose source, sink and mutation summaries must remain available.
        """
        adjacency = {engine: self.dependencies(engine) for _, _, engine, _ in self.sources}
        order = {engine: str(path) for path, _, engine, _ in self.sources}
        indices, lowlinks = {}, {}
        active, stacked = set(), []
        for root in sorted(adjacency, key=order.__getitem__):
            if root in indices:
                continue
            indices[root] = lowlinks[root] = len(indices)
            active.add(root)
            stacked.append(root)
            pending = [(root, iter(sorted(adjacency[root], key=order.__getitem__)))]
            while pending:
                engine, edges = pending[-1]
                dependency = next(edges, None)
                if dependency is not None:
                    if dependency not in indices:
                        indices[dependency] = lowlinks[dependency] = len(indices)
                        active.add(dependency)
                        stacked.append(dependency)
                        pending.append((dependency, iter(sorted(adjacency[dependency], key=order.__getitem__))))
                    elif dependency in active:
                        lowlinks[engine] = min(lowlinks[engine], indices[dependency])
                    continue
                pending.pop()
                if pending:
                    parent = pending[-1][0]
                    lowlinks[parent] = min(lowlinks[parent], lowlinks[engine])
                if lowlinks[engine] == indices[engine]:
                    component = []
                    while True:
                        member = stacked.pop()
                        active.remove(member)
                        component.append(member)
                        if member is engine:
                            break
                    yield sorted(component, key=order.__getitem__)

    def deferred_cycle(self, component):
        """Can every peer namespace be initialized before peer member access?

        Python permits `import peer` cycles and imports inside functions, but
        an eager `from peer import function`, decorator or initializer call
        may observe a partially initialized peer. Only accept explicit module
        imports, plain function definitions and literal module state here.
        Everything else retains the opaque fallback, never a guessed clean
        summary. No source is imported or executed to make this decision.
        """
        members = set(component)

        def literal(node):
            return node is None or all(isinstance(child, (
                ast.Constant, ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Load,
                ast.UnaryOp, ast.UAdd, ast.USub,
            )) for child in ast.walk(node))

        def annotation(node, engine):
            if node is None:
                return True
            # Builtin annotations cannot inspect a peer. Reject shadowed
            # builtin names, attribute lookups and executable annotations.
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    if (child.id not in {'str', 'bytes', 'int', 'float', 'bool', 'object',
                                         'list', 'tuple', 'dict', 'set', 'frozenset', 'type'}
                            or child.id in engine.global_names):
                        return False
                elif not isinstance(child, (ast.Constant, ast.Load, ast.Subscript,
                                            ast.Tuple, ast.BinOp, ast.BitOr)):
                    return False
            return True

        for engine in component:
            if self.modules.get(self.keys.get(engine)) is not engine:
                return False  # An ambiguous file/package name proves no identity.
            for node in engine.tree.body:
                if isinstance(node, (ast.Import, ast.Pass)):
                    continue
                if isinstance(node, ast.ImportFrom):
                    key = self.import_key(engine, node, node.module or '')
                    if self.modules.get(key) in members or any(alias.name == '*' for alias in node.names):
                        return False
                    continue
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                    continue
                if isinstance(node, ast.Assign):
                    if all(isinstance(target, ast.Name) for target in node.targets) and literal(node.value):
                        continue
                elif isinstance(node, ast.AnnAssign):
                    if (isinstance(node.target, ast.Name) and literal(node.value)
                            and annotation(node.annotation, engine)):
                        continue
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args = node.args
                    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
                    params.extend(arg for arg in (args.vararg, args.kwarg) if arg is not None)
                    if (not node.decorator_list and not getattr(node, 'type_params', ())
                            and all(literal(value) for value in (*args.defaults, *args.kw_defaults))
                            and annotation(node.returns, engine)
                            and all(annotation(arg.annotation, engine) for arg in params)):
                        continue
                elif isinstance(node, ast.ClassDef):
                    # Class bodies execute during import, but these bounded
                    # namespaces contain only literal state and deferred
                    # functions. Only an unshadowed builtin staticmethod
                    # decorator is safe to construct while peers initialize.
                    shadowed = engine.global_names | _local_names(node)
                    if (engine.plain_class(node, _State(bindings={name: None for name in engine.global_names}))
                            and all(isinstance(decorator, ast.Name) and decorator.id == 'staticmethod'
                                    and 'staticmethod' not in shadowed
                                    for member in node.body if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                                    for decorator in member.decorator_list)):
                        continue
                return False
        return True

    def analyze_cycle(self, component):
        # Publish all proven namespaces together. Priming does not solve any
        # function body and cannot read a peer member under deferred_cycle's
        # initializer contract. Qualified lookups then see complete namespaces.
        for engine in component:
            engine.globals = _Flow(engine, engine.tree).block(engine.tree.body, _State())
        self.ready.update(component)
        self.solving = set(component)
        try:
            while True:
                summaries = component[0].summaries.copy()
                effects = {}
                for engine in component:
                    for key, fact in engine.analyze().items():
                        effects[key] = join_facts(effects.get(key, CLEAN), fact)
                if summaries == component[0].summaries:
                    # Keep only the converged pass: an intermediate opaque
                    # return or provisional callable is not final evidence.
                    return effects
        finally:
            self.solving = set()

    def member(self, key, name, state):
        module_ref = '@module:' + str(key)
        if module_ref in state.mutated:
            # An attribute assignment/opaque mutation can replace an exported
            # callable or scalar. Do not keep certifying its old clean value.
            return state.heap.get(module_ref, CLEAN), None, frozenset({module_ref})
        engine = self.modules.get(key)
        if engine is not None and engine in self.ready and name in engine.globals:
            namespace = engine.globals
            refs = namespace.references.get(name, NO_REFERENCES)
            for ref in refs:
                state.heap[ref] = join_facts(state.heap.get(ref, CLEAN), namespace.heap.get(ref, CLEAN))
            fact = join_facts(namespace.value(name), *(state.heap.get(ref, CLEAN) for ref in refs))
            value = namespace.bindings.get(name)
            if refs & state.mutated:
                value = _without_object_contract(value)
            return fact, value, refs
        child = key / name
        if child in self.namespaces:
            binding = _ModuleBinding(self, child)
            return CLEAN, binding, frozenset({binding.reference})
        return CLEAN, None, NO_REFERENCES

    def imported(self, engine, node, alias, state):
        if alias.name == '*':
            return None  # Dynamic __all__ and wildcard bindings are not guessed.
        name = node.module or '' if isinstance(node, ast.ImportFrom) else alias.name
        key = self.import_key(engine, node, name)
        if key not in self.namespaces:
            return None  # External import: preserve the known library vocabulary.
        if isinstance(node, ast.ImportFrom):
            return self.member(key, alias.name, state)
        if not alias.asname:
            key = self.import_key(engine, node, alias.name.split('.')[0])
        binding = _ModuleBinding(self, key)
        return CLEAN, binding, frozenset({binding.reference})

    def findings(self):
        effects = {}
        for component in self.components():
            cyclic = len(component) > 1 or component[0] in self.dependencies(component[0])
            if cyclic and self.deferred_cycle(component):
                for key, fact in self.analyze_cycle(component).items():
                    effects[key] = join_facts(effects.get(key, CLEAN), fact)
                continue
            if cyclic:
                # Do not pretend to execute a cyclic import's partially
                # initialized modules. Keep this fallback within the actual
                # cycle, never disabling cross-file analysis in its callers.
                for engine in component:
                    engine.project = None
            for engine in component:
                for key, fact in engine.analyze().items():
                    effects[key] = join_facts(effects.get(key, CLEAN), fact)
                self.ready.add(engine)
        starts = [offset for _, _, _, offset in self.sources]
        indexes = {path: build_index(text, lang='python') for path, text, _, _ in self.sources}
        for (kind, line, column, label), fact in sorted(effects.items(), key=lambda item: (item[0][1], item[0][2], item[0][0])):
            path, _, _, offset = self.sources[bisect_right(starts, line - 1) - 1]
            line -= offset
            rule = f'py.taint.{kind}'
            if indexes[path].is_suppressed(line, rule) or indexes[path].is_suppressed(line, f'python.taint.{kind}'):
                continue
            trace = min(fact, key=lambda item: (len(item.path), item.path, item.source))
            yield path, rule, line, column, ' -> '.join((*trace.path, label))


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in EXTS:
            yield root
        return
    for path in root.rglob('*'):
        if not path.is_file(): continue
        # Prune below the walk root only: the checkout may itself live under
        # a directory named build/ or dist/ (GH #151).
        if should_skip(path.relative_to(root)): continue
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
    for path, rule, line, _col, description in _Project(iter_files(ROOT), BASE_DIR).findings():
        bucket = issues[rule]
        bucket['count'] += 1
        if len(bucket['samples']) < 3:
            bucket['samples'].append(f'{path.relative_to(BASE_DIR)}:{line} {description}')
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
    for path, rule, line, col, path_desc in _Project(ctx.files, ctx.profile.get('project_dir')).findings():
        kind = KIND_BY_RULE[rule]
        if not ctx.rule_enabled(f'python.taint.{kind}') or not ctx.rule_enabled(rule):
            continue
        yield {
            "rule": f"python.taint.{kind}",
            "path": str(path),
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
