"""Function-scoped Python taint analysis with local call summaries (bead D6).

The AST transfer functions use strong assignment updates, join control-flow
branches, and iterate loops and recursive function summaries to a fixpoint.
Facts retain source provenance and sink-specific sanitizers. Local helpers
summarize both returned values and parameters reaching a sink; analyzed code
is never imported or executed. Selected Python modules share function
summaries, including qualified cycles with deferred peer lookups. Unresolved
imports, eager cyclic initialization and arbitrary dynamic dispatch retain
conservative opaque-call behavior. Known callable aliases and builtin
classmethod descriptors retain captured receivers through local summaries.
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
import tokenize
from bisect import bisect_right
from collections import defaultdict, deque
from dataclasses import dataclass, field, fields, is_dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Union

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import build_index
from ubs_core.taint_flow import AnalysisLimit, Budget

ROOT: Path = Path()
BASE_DIR: Path = Path()
SKIP_DIRS = {'.git', '.venv', '__pycache__', 'node_modules', '.mypy_cache', '.pytest_cache', '.cache', 'build', 'dist'}
EXTS = {'.py', '.pyi'}
PATH_LIMIT = 5
_INCOMPLETE_PROOF = 'taint:incomplete'
_MAX_CAPTURE_DEPTH = 64
_PARTIAL_MODULE_REF = '@stdlib:functools'
_PARTIAL_CHANGED_MODULE = '@partial:changed-module'
_PARTIAL_CHANGED_CONSTRUCTOR = '@partial:changed-constructor'
# Keep a precise prefix plus an aggregate unknown-length suffix in summaries.
_MAX_VECTOR_CONTEXT = 16


def _work_setting(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise AnalysisLimit(f'{name} must be a positive integer; analysis is incomplete') from exc
    if value <= 0:
        raise AnalysisLimit(f'{name} must be a positive integer; analysis is incomplete')
    return value


def _distinct_components(components):
    """Collapse repeated callback failures without discarding their locations."""
    distinct, seen = [], set()
    for item in components:
        key = (item['file'], item['symbol'], item['start_line'], item['end_line'], item['reason'])
        if key not in seen:
            seen.add(key)
            distinct.append(item)
    return tuple(distinct)


class _ScopeIncomplete(AnalysisLimit):
    """A function cannot finish; independent scopes can still be analyzed."""


class _ScopeLimit(_ScopeIncomplete):
    """A function exhausted its own allowance, not the total file budget."""


class _ScopedBudget:
    """Charge both the file and a function across all of its summary contexts."""

    def __init__(self, engine, scope, total):
        self.engine, self.scope, self.total = engine, scope, total

    @property
    def remaining(self):
        return self.total.remaining

    def spend(self, amount=1):
        # Check the total first: a genuine file cutoff must still abort the
        # component, including foreign callback work charged to its owner.
        self.total.spend(amount)
        remaining = self.engine.scope_remaining[self.scope] - amount
        self.engine.scope_remaining[self.scope] = remaining
        if remaining < 0:
            limit = self.engine.scope_limits[self.scope]
            reason = f'function work limit exceeded ({limit} steps); analysis is incomplete'
            raise _ScopeLimit(f'{self.engine.scope_name(self.scope)}: {reason}',
                              components=(self.engine.scope_diagnostic(self.scope, reason),))

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
_SOURCE_FAST_RE = re.compile('|'.join(f'(?:{p.pattern})' for p in SOURCE_PATTERNS), re.IGNORECASE)

SANITIZERS = {
    'html.escape': 'xss', 'django.utils.html.escape': 'xss',
    'django.utils.html.conditional_escape': 'xss', 'flask.escape': 'xss',
    'markupsafe.escape': 'xss', 'bleach.clean': 'xss',
    'shlex.quote': 'command',
}

KIND_BY_RULE = {f'py.taint.{kind}': kind for kind in ('xss', 'sql', 'command', 'eval', 'ssrf')}

# These are resolved import identities, not method-name heuristics. A mapping
# lookup or an unrelated object's get() must never acquire an HTTP contract.
# request()/stream() take a method before their URL; convenience calls do not.
# Bodies, query parameters, headers and authentication are not URL operands.
_HTTP_URL_POSITIONS = {
    **{f'{module}.{method}': 0
       for module in ('requests', 'requests.api', 'httpx')
       for method in ('get', 'post', 'put', 'patch', 'delete', 'head', 'options')},
    'requests.request': 1,
    'requests.api.request': 1,
    'httpx.request': 1,
    'httpx.stream': 1,
}


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
_ALL_FRAMEWORK_NAMES = frozenset(
    _PARAMETER_MARKERS | _DEPENDENCY_MARKERS | _ROUTER_TYPES | _REQUEST_TYPES | _SERVICE_TYPES
)
_FASTAPI_ROUTE_DECORATORS = frozenset(f'@fastapi.router.{method}' for method in _ROUTE_METHODS)


@dataclass(frozen=True)
class _FrameworkInput:
    kind: str
    name: str
    dependency: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    native_string: bool = False


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
    if isinstance(target, _ClosureValue):
        target = target.value
    if any(isinstance(choice, _PartialValue) for choice in _binding_choices(target)):
        raise AnalysisLimit('functools.partial framework dependency needs callback binding analysis; '
                            'analysis is incomplete')
    if isinstance(target, _FunctionValue):
        target = target.function
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
    _hash: int = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, '_hash', hash((self.source, self.parameter, self.sanitizers)))

    def __hash__(self) -> int:
        return self._hash


Fact = frozenset[TaintTrace]
CLEAN: Fact = frozenset()
# Allocation sites are AST nodes, while strings name symbolic argument,
# closure, or module objects. Both sets are finite even inside recursion.
# A runtime alias, not an annotation: `ast.AST | str` would be evaluated and
# raise TypeError on Python 3.9, which ubs still supports (python_is_3).
References = frozenset[Union[ast.AST, str]]
NO_REFERENCES: References = frozenset()
_MISSING = object()  # absent-key sentinel for the state join
_NAMESPACE_PRESENT = '@namespace:present'
_NAMESPACE_ABSENT = '@namespace:absent'
_NAMESPACE_MAYBE = '@namespace:maybe'


@dataclass(frozen=True)
class _CallTarget:
    """Callable and receiver identities captured before argument evaluation."""
    binding: object
    fallback_name: str = ''
    receiver: Fact = CLEAN
    references: References = NO_REFERENCES


@dataclass(frozen=True)
class _CallInputs:
    """Already evaluated arguments; keep keyword facts with their AST nodes."""
    arguments: list[Fact]
    keywords: dict[str | None, Fact]
    keyword_nodes: dict[str | None, ast.AST]


@dataclass(frozen=True)
class _BoundCallable:
    name: str
    references: References
    receiver: Fact = CLEAN
    # Import qualifiers identify an API; invented receiver paths do not.
    namespace_proven: bool = False


@dataclass(frozen=True)
class _GlobalNamespace:
    """A real globals() mapping, distinct from a same-spelled user object."""
    module: ast.Module
    member: str | None = None


@dataclass(frozen=True)
class _ClassMethodDescriptor:
    function: ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True)
class _BoundClassMethod:
    """A descriptor lookup captures its function, class and receiver identity.

    Replacing a class member does not replace an already captured callable.
    It can, however, invalidate proofs about members read through its receiver.
    """
    function: ast.FunctionDef | ast.AsyncFunctionDef
    owner: ast.ClassDef
    references: References
    receiver: Fact = CLEAN
    valid: bool = True


@dataclass(frozen=True)
class _LiteralString:
    """A value is not an import/callable identity just because it is text."""
    value: str
    # Exact contents do not prove that producing this value had an inert
    # lifetime. Keep that narrower authority with aliases and call summaries.
    format_safe: bool = True


@dataclass(frozen=True)
class _LiteralMapping:
    """An exact builtin dict created solely from immutable scalar literals.

    The finite marker proves that selecting a key does not copy that key into
    the returned value. Writes or opaque escapes revoke this contract; it is
    never inferred from a name, annotation or an arbitrary get() method.
    """


_LITERAL_MAPPING_GET = '@literal-mapping.get'


@dataclass(frozen=True)
class _SymbolicValue:
    parameter: str


@dataclass(frozen=True)
class _ArgumentVector:
    # Fixed constructions retain positions; opaque expansions retain unknown
    # lengths. Writes/escapes invalidate the shape instead of assigning a heap
    # fact to a guessed operand.
    operands: tuple
    # The outer container and its elements have different identities. Keep
    # evaluated element aliases beside their facts so wrapper projections and
    # returned slices still observe writes through an independent inner alias.
    # Empty metadata is retained for older/internal shape-only constructions.
    references: tuple = ()

    def references_at(self, index):
        return self.references[index] if self.references else NO_REFERENCES


@dataclass(frozen=True)
class _ArgumentExpansion:
    """An unknown-length argv segment, never a single positional operand."""


def _literal_choices(binding):
    """Scalar argv alternatives carry literals or unknown, never object graphs.

    Nested vectors/callables have independent facts and aliases. Retaining
    them inside a scalar choice would leak concrete captures into context
    keys and could certify an object's stale shape after a heap write.
    """
    if isinstance(binding, frozenset):
        return frozenset(value if isinstance(value, _LiteralString) else None for value in binding)
    return binding


def _vector_shape(vector):
    return tuple(_literal_choices(operand)
                 if isinstance(operand, (_LiteralString, _ArgumentExpansion, frozenset)) else None
                 for operand, _fact in vector.operands)


def _context_vector(vector):
    if len(vector.operands) <= _MAX_VECTOR_CONTEXT:
        return vector
    # Retain the executable and a bounded option prefix. The rest remains an
    # unknown-length segment with ALL of its taint, including recursive growth.
    references = ((*vector.references[:_MAX_VECTOR_CONTEXT],
                   frozenset().union(*vector.references[_MAX_VECTOR_CONTEXT:]))
                  if vector.references else ())
    return _ArgumentVector((*vector.operands[:_MAX_VECTOR_CONTEXT],
                            (_ArgumentExpansion(), join_facts(*(
                                fact for _operand, fact in vector.operands[_MAX_VECTOR_CONTEXT:])))),
                           references)


def _vector_variants(binding):
    """Group equal program/option shapes without cross-pairing their facts.

    Contexts contain only bounded shapes and source-level literal identities.
    Recursive argv growth widens the suffix; taint is never discarded.
    """
    if not isinstance(binding, (_ArgumentVector, frozenset)):
        return []
    shapes = {}
    for value in _binding_choices(binding):
        if isinstance(value, _ArgumentVector):
            value = _context_vector(value)
            shapes.setdefault(_vector_shape(value), []).append(value)
    return [(index, shape, shapes[shape])
            for index, shape in enumerate(sorted(shapes, key=repr))]


def _vector_slot(name, variant, index):
    return f'@argv:{name}:{variant}:{index}'


@dataclass(frozen=True)
class _ProcessInput:
    """Finite stdin-source contract, independent of process identity or taint."""
    kind: str


@dataclass(frozen=True)
class _CellRef:
    """A lexical allocation site with at most two enclosing call sites."""
    owner: ast.AST
    name: str
    sites: tuple = ()


@dataclass(frozen=True)
class _CellContents:
    fact: Fact = CLEAN
    references: References = NO_REFERENCES
    binding: object = None
    # None means a join of bound and deleted/uninitialized alternatives.
    bound: bool | None = True


def _join_cells(left, right):
    if left is right:
        return left
    return _CellContents(join_facts(left.fact, right.fact), left.references | right.references,
                         _join_bindings(left.binding, right.binding),
                         left.bound if left.bound == right.bound else None)


@dataclass(frozen=True)
class _GlobalWrite:
    """A module replacement and the value on a branch that did not write.

    Unlike heap mutations these are strong assignments. Retaining the entry
    value lets a lazily allocated record join an unwritten branch without
    discarding that branch's original fact, callable identity or object alias.
    """
    initial: _CellContents
    current: _CellContents
    raw_global: bool = False


@dataclass(frozen=True, eq=False)
class _ClosureValue:
    """A callable owns cell identities; their live contents belong to state."""
    value: object
    cells: tuple
    depth: int = field(init=False, compare=False)
    _hash: int = field(init=False, compare=False, repr=False)

    @property
    def function(self):
        return self.value.function if isinstance(self.value, _FunctionValue) else self.value

    def __post_init__(self):
        depth = 1 + getattr(self.value, 'depth', 0)
        if depth > _MAX_CAPTURE_DEPTH:
            raise AnalysisLimit(f'Python captured-default nesting exceeds {_MAX_CAPTURE_DEPTH} levels')
        object.__setattr__(self, 'depth', depth)
        object.__setattr__(self, '_hash', hash((self.value, self.cells)))

    def __hash__(self):
        return self._hash

    def __eq__(self, other):
        return type(other) is type(self) and _same_analysis_value(self, other)


@dataclass(frozen=True)
class _CellGraph:
    """Canonical call-context cells; contents here contain identities only."""
    roots: tuple = ()
    entries: tuple = ()


class _CellState:
    """Allocated lazily so scopes without closures keep their old state cost."""
    def __init__(self):
        self.names = {}
        self.contents = {}
        self.written = set()
        self.multiple = set()

    def copy(self):
        other = _CellState()
        other.names = self.names.copy()
        other.contents = self.contents.copy()
        other.written = self.written.copy()
        other.multiple = self.multiple.copy()
        return other

    def __eq__(self, other):
        return (isinstance(other, _CellState) and self.names == other.names
                and self.contents == other.contents and self.written == other.written
                and self.multiple == other.multiple)


@dataclass(frozen=True, eq=False)
class _FunctionValue:
    """One function creation owns its evaluated defaults.

    The AST identifies the body, but does not identify a factory invocation.
    Keep captured facts and aliases here, outside callable context keys.
    """

    function: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
    arguments: tuple = field(repr=False)
    references: tuple = field(repr=False)
    values: tuple = field(repr=False)
    depth: int = field(init=False, compare=False)
    _hash: int = field(init=False, compare=False, repr=False)

    def __post_init__(self):
        _capture_metadata(self)

    def __hash__(self):
        return self._hash

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return _same_analysis_value(self, other)


@dataclass(frozen=True, eq=False)
class _PartialValue(_FunctionValue):
    """A partial's creation site identifies captured callable/operand slots.

    Reuse evaluated-default transport for facts, object aliases and lexical
    cells. The creation site is not an executable function: only invoking this
    value combines its captured operands with the new call's arguments.
    """

    function: ast.Call


@dataclass(frozen=True, eq=False)
class _DeferredCall:
    """Known coroutine creation captures arguments, not execution effects."""

    function: ast.AsyncFunctionDef
    call: ast.Call
    arguments: tuple = field(repr=False)
    references: tuple = field(repr=False)
    values: tuple = field(default=(), repr=False)
    cells: tuple = field(default=(), repr=False)
    depth: int = field(init=False, compare=False)
    _hash: int = field(init=False, compare=False, repr=False)

    def __post_init__(self):
        _capture_metadata(self)

    def __hash__(self):
        return self._hash

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return _same_analysis_value(self, other)


@dataclass(frozen=True, eq=False)
class _DeferredGenerator(_DeferredCall):
    """A bounded generator owns captured operands and a state-local cursor.

    The reserved cell records progress, separately from the immutable handle.
    Copying a handle aliases that cell; copying a branch copies its contents.
    """


@dataclass(frozen=True, eq=False)
class _GeneratorNext(_FunctionValue):
    """The immutable __next__ method of one known generator instance."""


@dataclass(frozen=True)
class _GeneratorString:
    """A proven builtin string, with unknown contents and no literal contract."""
    format_safe: bool = True


_GENERATOR_CURSOR = '@generator:cursor'
_GENERATOR_CREATED = '@generator:created'
_GENERATOR_SUSPENDED = '@generator:suspended'
_GENERATOR_EXHAUSTED = '@generator:exhausted'
_PREDICATE_RESULTS = (ast.Constant(value=False), ast.Constant(value=True))


def _literal_execution_authority(nodes):
    """Inspect literal eval/exec syntax only for exposed execution authority.

    Embedded code never participates in ordinary flow or source positions.
    The bounded extra syntax merely revokes native identities using the same
    reflection/namespace inventory as source code. Unknown computed strings
    remain outside this proof; exceeding its bounds must not certify them.
    """
    pending = [node for node in nodes if isinstance(node, ast.Call)]
    extra, seen = [], set()
    characters, remaining = 65_536, 4_096
    while pending:
        call = pending.pop()
        spelling = (call.func.id if isinstance(call.func, ast.Name)
                    else call.func.attr if isinstance(call.func, ast.Attribute) else None)
        if (spelling not in {'eval', 'exec'} or not call.args
                or not isinstance(call.args[0], ast.Constant)
                or type(call.args[0].value) not in {str, bytes}):
            continue
        source = call.args[0].value
        key = (spelling, source)
        if key in seen:
            continue
        seen.add(key)
        characters -= len(source)
        if characters < 0:
            return tuple(extra), True
        if spelling == 'eval':
            # eval strips spaces/tabs before compiling; ast.parse does not.
            # Keep that distinction from hiding a valid indented payload.
            source = source.strip(b' \t' if isinstance(source, bytes) else ' \t')
        try:
            tree = ast.parse(source, mode=spelling)
        except (SyntaxError, UnicodeError):
            continue  # Native execution also fails before this code can run.
        except RecursionError:
            return tuple(extra), True
        for node in ast.walk(tree):
            remaining -= 1
            if remaining < 0:
                return tuple(extra), True
            extra.append(node)
            if isinstance(node, ast.Call):
                pending.append(node)
    return tuple(extra), False


def _readonly_builtin_modules(nodes, parents):
    """Recognize private imports used only to call selected native builtins.

    Importing builtins does not itself mutate input/next, but an escaped
    module alias would expose every member. Reject rebinding and every use
    beyond a direct supported call, including namespace reads and stores.
    """
    if any(isinstance(node, ast.ImportFrom) and any(alias.name == '*' for alias in node.names)
           for node in nodes):
        return frozenset()  # Exported names can replace even an earlier module alias.
    names = {alias.asname or alias.name for node in nodes if isinstance(node, ast.Import)
             for alias in node.names if alias.name == 'builtins'}
    allowed = {'input', 'list', 'tuple', 'any', 'all', 'next'}
    result = set()
    for name in names:
        valid = True
        for node in nodes:
            if isinstance(node, ast.Name) and node.id == name:
                attribute = parents.get(node)
                call = parents.get(attribute)
                if not (isinstance(node.ctx, ast.Load) and isinstance(attribute, ast.Attribute)
                        and attribute.value is node and isinstance(attribute.ctx, ast.Load)
                        and attribute.attr in allowed and isinstance(call, ast.Call) and call.func is attribute):
                    valid = False
                    break
            elif (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name
                  or isinstance(node, ast.arg) and node.arg == name
                  or isinstance(node, ast.ExceptHandler) and node.name == name):
                valid = False
                break
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                if any((alias.asname or alias.name.split('.')[0]) == name
                       and not (isinstance(node, ast.Import) and alias.name == 'builtins') for alias in node.names):
                    valid = False
                    break
        if valid:
            result.add(name)
    return frozenset(result)


def _terminal_generator(function):
    """One direct yield has a finite continuation with no source suffix.

    Reads are checked again at resumption. Assignments, calls, iteration,
    delegation and cleanup require additional suspension/effect semantics.
    """
    if (not isinstance(function, ast.FunctionDef) or function.decorator_list
            or getattr(function, 'type_params', ()) or function.type_comment
            or function.returns is not None):
        return False
    signature = function.args
    if (signature.vararg is not None or signature.kwarg is not None
            or any(argument.annotation is not None for argument in
                   (*signature.posonlyargs, *signature.args, *signature.kwonlyargs))):
        return False
    body = function.body
    if not (body and isinstance(body[-1], ast.Expr)
            and isinstance(body[-1].value, ast.Yield)
            and (body[-1].value.value is None
                 or isinstance(body[-1].value.value, (ast.Name, ast.Constant)))):
        return False
    return all(isinstance(statement, (ast.Pass, ast.Global, ast.Nonlocal))
               or index == 0 and isinstance(statement, ast.Expr)
               and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str)
               for index, statement in enumerate(body[:-1]))


def _capture_metadata(value):
    """Bound the mixed capture graph and cache its immutable semantic hash.

    A coroutine can capture a function whose default is another coroutine.
    Count both kinds, and hash each already-created child in constant time.
    This also avoids repeated tuple hashing on Python versions before 3.14.
    """
    depth = 1 + max((child.depth for _, binding in value.values
                     for child in (binding if isinstance(binding, frozenset) else (binding,))
                     if isinstance(child, (_FunctionValue, _DeferredCall, _ClosureValue))), default=0)
    if depth > _MAX_CAPTURE_DEPTH:
        raise AnalysisLimit(f'Python captured-default nesting exceeds {_MAX_CAPTURE_DEPTH} levels')
    object.__setattr__(value, 'depth', depth)
    parts = (value.function, value.arguments, value.references, value.values)
    if isinstance(value, _DeferredCall):
        parts = (value.call, value.cells, *parts)
    object.__setattr__(value, '_hash', hash(parts))


def _same_analysis_value(left, right, *, witness=False):
    """Compare an immutable DAG once per pair, optionally retaining evidence.

    Captures can share the same child through several defaults. Recursive
    dataclass/tuple equality expands those edges exponentially even when
    the graph itself is small. The memo belongs only to this comparison;
    evidence checks share it with semantic matching of unordered choices.
    """
    if left is right:
        return True
    compared = {}
    pending = []
    request = (left, right, witness)
    while True:
        a, b, evidence = request
        if a is b:
            result = True
        else:
            key = (id(a), id(b), evidence)
            result = compared.get(key, _MISSING)
            if result is _MISSING:
                frame = _analysis_comparison_steps(a, b, evidence)
                try:
                    request = next(frame)
                except StopIteration as done:
                    result = done.value
                    compared[key] = result
                else:
                    pending.append((key, frame))
                    continue
        while pending:
            key, frame = pending[-1]
            try:
                request = frame.send(result)
            except StopIteration as done:
                result = done.value
                compared[key] = result
                pending.pop()
            else:
                break
        else:
            return result


def _analysis_comparison_steps(a, b, evidence):
    """Yield child comparisons in order; the driver owns the stack and memo."""
    if isinstance(a, _ClosureValue):
        return (type(a) is type(b) and a._hash == b._hash and a.cells == b.cells
                and (yield (a.value, b.value, evidence)))
    if isinstance(a, _CellContents):
        return (type(a) is type(b) and a.bound == b.bound and a.references == b.references
                and (yield (a.fact, b.fact, evidence))
                and (yield (a.binding, b.binding, evidence)))
    if isinstance(a, _GlobalWrite):
        return (type(a) is type(b) and a.raw_global == b.raw_global
                and (yield (a.initial, b.initial, evidence))
                and (yield (a.current, b.current, evidence)))
    if isinstance(a, (_FunctionValue, _DeferredCall)):
        return (type(a) is type(b) and a._hash == b._hash
                and a.function is b.function
                and (not isinstance(a, _DeferredCall) or a.call is b.call)
                and (not isinstance(a, _DeferredCall) or a.cells == b.cells)
                and (yield (a.arguments, b.arguments, evidence))
                and (yield (a.references, b.references, evidence))
                and (yield (a.values, b.values, evidence)))
    if isinstance(b, (_FunctionValue, _DeferredCall)):
        return False
    if isinstance(a, TaintTrace):
        return a == b and (not evidence or a.path == b.path)
    if isinstance(a, tuple):
        if not isinstance(b, tuple) or len(a) != len(b):
            return False
        for x, y in zip(a, b):
            if not (yield (x, y, evidence)):
                return False
        return True
    if isinstance(a, frozenset):
        if not isinstance(b, frozenset) or len(a) != len(b):
            return False
        buckets = {}
        for candidate in b:
            buckets.setdefault(hash(candidate), []).append(candidate)
        for item in a:
            for candidate in buckets.get(hash(item), ()):
                if (yield (item, candidate, False)):
                    # Preserve first semantic match, then its evidence check;
                    # the missing sentinel itself never proves a match.
                    if candidate is _MISSING or evidence and not (yield (item, candidate, True)):
                        return False
                    break
            else:
                return False
        return True
    if isinstance(a, _BoundCallable):
        return (type(a) is type(b) and a.name == b.name and a.references == b.references
                and (yield (a.receiver, b.receiver, evidence)))
    if isinstance(a, _BoundClassMethod):
        return (type(a) is type(b) and (yield (a.function, b.function, evidence))
                and a.owner is b.owner and a.references == b.references and a.valid == b.valid
                and (yield (a.receiver, b.receiver, evidence)))
    if isinstance(a, _ArgumentVector):
        return (type(a) is type(b) and a.references == b.references
                and (yield (a.operands, b.operands, evidence)))
    return a == b


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
    'eval', 'exec', 'input', 'raw_input', 'print', 'str', 'list', 'tuple', 'any', 'all', 'next', 'globals', 'builtins', 'staticmethod', 'classmethod',
    'html', 'django', 'flask', 'markupsafe', 'bleach', 'shlex', 'subprocess', 'os', 'asyncio',
    'sys', 'request', 'cursor', 'session', 'conn', 'engine', 'db',
    'render_template', 'render_template_string', 'HttpResponse', 'Response',
})
_IMPLICIT_IDENTITY_MAP = {
    **{
        name: 'builtins.' + name
        for name, value in vars(builtins).items()
        if isinstance(value, type) and issubclass(value, BaseException)
    },
    **{name: name for name in _IMPLICIT_IDENTITIES},
}


def _implicit_identity(name):
    return _IMPLICIT_IDENTITY_MAP.get(name)


def _binding_choices(binding):
    return binding if isinstance(binding, frozenset) else frozenset({binding})


def _join_bindings(*bindings):
    n = len(bindings)
    if n == 1:
        only = bindings[0]
        if type(only) is not frozenset:  # ubs:ignore[py.comparison.type-equality,py.type-equality]
            return only
        return next(iter(only)) if len(only) == 1 else only
    if n == 2:
        a, b = bindings
        if a is b:
            if type(a) is not frozenset:  # ubs:ignore[py.comparison.type-equality,py.type-equality]
                return a
            return next(iter(a)) if len(a) == 1 else a
        ca = a if isinstance(a, frozenset) else frozenset({a})
        cb = b if isinstance(b, frozenset) else frozenset({b})
        choices = ca | cb
        return next(iter(choices)) if len(choices) == 1 else choices
    if bindings:
        first = bindings[0]
        same = True
        for b in bindings[1:]:
            if b is not first:
                same = False
                break
        if same:
            if type(first) is not frozenset:  # ubs:ignore[py.comparison.type-equality,py.type-equality]
                return first
            return next(iter(first)) if len(first) == 1 else first
    choices = frozenset().union(*(_binding_choices(binding) for binding in bindings))
    if len(choices) == 1:
        return next(iter(choices))
    return choices  # Empty means no known return yet; None means unknown.


def _without_object_contract(binding):
    if any(isinstance(value, _PartialValue) for value in _binding_choices(binding)):
        raise AnalysisLimit('mutated functools.partial object; analysis is incomplete')
    choices = []
    for value in _binding_choices(binding):
        if isinstance(value, (_ArgumentVector, _LiteralMapping, _ProcessInput, ast.ClassDef)):
            value = None
        elif isinstance(value, _BoundCallable) and value.name == _LITERAL_MAPPING_GET:
            value = _BoundCallable('<object>.get', value.references, value.receiver)
        elif value == 'functools':
            value = _PARTIAL_CHANGED_MODULE
        choices.append(value)
    return _join_bindings(*choices)


_QUALIFIER_WIDTH = max(4, *(candidate.count('.') + 1 for candidate in SANITIZERS))
_KNOWN_QUALIFIER_PREFIXES = frozenset(
    '.'.join(qualified.split('.')[:size])
    for qualified in (*SANITIZERS, *_HTTP_URL_POSITIONS, *_ALL_FRAMEWORK_NAMES, *_REQUEST_TYPES)
    for size in range(1, len(qualified.split('.')) + 1))


def _opaque_qualifier(name: str, *, receiver_unknown=False) -> str:
    """Forget unproved intermediate receiver paths, retaining recognizers."""
    parts = name.split('.')
    opaque = next((index for index, part in enumerate(parts)
                   if part in {'<object>', '<unknown>'}), None)
    if name not in _KNOWN_QUALIFIER_PREFIXES and not any(pattern.search(name + '(') for pattern in SOURCE_PATTERNS):
        if opaque is not None and opaque + 2 < len(parts):
            return '.'.join([*parts[:opaque + 1], parts[-1]])
        if receiver_unknown and opaque is None and len(parts) > 2:
            return '.'.join((parts[0], '<unknown>', parts[-1]))
    return name


def _extend_qualifier(base: str, attribute: str, *, receiver_unknown=False) -> str:
    """Keep name identities finite without dropping value or receiver facts.

    Recognizers need an exact known API name, the root SQL handle, the final
    method, or up to three trailing source components. A non-identifier marker
    prevents long unknown paths from acquiring an exact sanitizer identity.
    """
    name = _opaque_qualifier(f'{base}.{attribute}', receiver_unknown=receiver_unknown)
    if name.count('.') < _QUALIFIER_WIDTH:
        return name
    components = name.split('.')
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
    n = len(facts)
    if n == 0:
        return CLEAN
    if n == 1:
        only = facts[0]
        if not only:
            return CLEAN
        if type(only) is frozenset:  # ubs:ignore[py.comparison.type-equality,py.type-equality]
            return only
    elif n == 2:
        a, b = facts
        if not a:
            if not b:
                return CLEAN
            if type(b) is frozenset:  # ubs:ignore[py.comparison.type-equality,py.type-equality]
                return b
        elif (not b or a is b) and type(a) is frozenset:  # ubs:ignore[py.comparison.type-equality,py.type-equality]
            return a
    head = None
    same = True
    for fact in facts:
        if not fact:
            continue
        if head is None:
            head = fact
        elif fact is not head:
            same = False
            break
    if head is None:
        return CLEAN
    # A lone fact, or one fact object joined with itself, is its own join:
    # its traces are already distinct. Returning it keeps object identity,
    # which lets repeated state joins take the identity fast path below.
    if same and type(head) is frozenset:  # ubs:ignore[py.comparison.type-equality,py.type-equality] - exact type on purpose: only a plain frozenset is known immutable with stock hashing/equality.
        return head
    traces: dict[TaintTrace, TaintTrace] = {}
    for fact in facts:
        if not fact:
            continue
        for trace in fact:
            previous = traces.get(trace)
            if previous is None or (len(trace.path), trace.path) < (len(previous.path), previous.path):
                traces[trace] = trace
    return frozenset(traces.values())


@lru_cache(maxsize=1024)
def _advance_trace(source, parameter, sanitizers, path, steps, limit):
    """Cache a complete immutable witness transformation, including its limit."""
    path = list(path)
    for step in steps:
        if not path or path[-1] != step:
            path.append(step)
    if len(path) > limit:
        path = [path[0], *path[-(limit - 1):]]
    return TaintTrace(source, parameter, sanitizers, tuple(path))


def _advance(fact: Fact, *steps: str) -> Fact:
    if not fact or not steps:
        return fact
    traces = []
    for trace in fact:
        # Trace equality omits paths; every witness field is a cache input.
        traces.append(_advance_trace(
            trace.source, trace.parameter, trace.sanitizers, trace.path, steps, PATH_LIMIT))
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


def _interpreter_inputs(kind, arguments, literal_text=_literal_text):
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
        option = literal_text(node)
        if option is None:
            if shell_command and not isinstance(node, (ast.Starred, _ArgumentExpansion)):
                return fact, CLEAN
            return CLEAN, join_facts(*(value for _node, value in arguments[index:]))
        if option == '--':
            if index + 1 < len(arguments) and isinstance(arguments[index + 1][0], (ast.Starred, _ArgumentExpansion)):
                return CLEAN, join_facts(*(value for _node, value in arguments[index + 1:]))
            value = arguments[index + 1][1] if index + 1 < len(arguments) else CLEAN
            return (value, CLEAN) if shell_command else (CLEAN, value)
        if option == '-' or not option.startswith(('-', '+')):
            # A dynamic script path is executable input; a fixed script path
            # is clean regardless of what follows in its application argv.
            return (fact, CLEAN) if shell_command else (CLEAN, fact)
        takes_value = ({'-o', '+o', '-O', '+O', '--rcfile', '--init-file'} if kind == 'shell'
                       else {'-W', '-X', '--check-hash-based-pycs'})
        if option in takes_value:
            if index + 1 < len(arguments) and isinstance(arguments[index + 1][0], (ast.Starred, _ArgumentExpansion)):
                # Only one element is the option value. An opaque/widened
                # segment can also contain a later -c and its source text.
                return CLEAN, join_facts(*(value for _node, value in arguments[index + 1:]))
            index += 2
            continue
        if option.startswith('-') and not option.startswith('--'):
            if kind == 'python':
                for position, flag in enumerate(option[1:], 2):
                    if flag in {'c', 'm'}:
                        # The rest of this option is code/module text, not
                        # additional flags. -W/-X values must never supply c.
                        if (not option[position:] and index + 1 < len(arguments)
                                and isinstance(arguments[index + 1][0], (ast.Starred, _ArgumentExpansion))):
                            return CLEAN, join_facts(*(value for _node, value in arguments[index + 1:]))
                        value = fact if option[position:] else (
                            arguments[index + 1][1] if index + 1 < len(arguments) else CLEAN)
                        return CLEAN, value
                    if flag in {'W', 'X'}:
                        if not option[position:]:
                            if (index + 1 < len(arguments)
                                    and isinstance(arguments[index + 1][0], (ast.Starred, _ArgumentExpansion))):
                                return CLEAN, join_facts(*(value for _node, value in arguments[index + 1:]))
                            index += 1
                        break
            elif 'c' in option[1:]:
                shell_command = True
        index += 1
    return CLEAN, CLEAN


def _interpreter_reads_stdin(kind, arguments, literal_text=_literal_text):
    """Whether stdin may be executable source, rather than application data."""
    index = 0
    shell_stdin = False
    while index < len(arguments):
        option = literal_text(arguments[index][0])
        if option is None:
            return True
        if option == '--':
            return (shell_stdin or index + 1 == len(arguments)
                    or isinstance(arguments[index + 1][0], (ast.Starred, _ArgumentExpansion))
                    or literal_text(arguments[index + 1][0]) == '-')
        if option == '-':
            return True
        if not option.startswith(('-', '+')):
            return shell_stdin
        consumes = ({'-o', '+o', '-O', '+O', '--rcfile', '--init-file'} if kind == 'shell'
                    else {'-W', '-X', '--check-hash-based-pycs'})
        if option in consumes:
            if index + 1 < len(arguments) and isinstance(arguments[index + 1][0], (ast.Starred, _ArgumentExpansion)):
                return True
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
                            if (index + 1 < len(arguments)
                                    and isinstance(arguments[index + 1][0], (ast.Starred, _ArgumentExpansion))):
                                return True
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
        cells = getattr(values, 'cells', None)
        self.cells = cells.copy() if cells is not None else None
        global_writes = getattr(values, 'global_writes', None)
        self.global_writes = global_writes.copy() if global_writes is not None else None
        self.deleted_globals = getattr(values, 'deleted_globals', frozenset())
        self.maybe_unbound = getattr(values, 'maybe_unbound', frozenset())
        self.reachable = getattr(values, 'reachable', True)

    def cell_state(self):
        if self.cells is None:
            self.cells = _CellState()
        return self.cells

    def put_cell(self, ref, contents, *, written=False, weak=False):
        cells = self.cell_state()
        if weak and ref in cells.contents:
            contents = _join_cells(cells.contents[ref], contents)
        cells.contents[ref] = contents
        if written:
            cells.written.add(ref)
        for name, target in cells.names.items():
            if target == ref:
                self[name] = contents.fact
                self.bindings[name] = contents.binding
                self.references[name] = contents.references
                self.maybe_unbound = (self.maybe_unbound - {name} if contents.bound is True
                                      else self.maybe_unbound | {name})

    def value(self, name):
        base = self.get(name, CLEAN)
        heap = self.heap
        if not heap:
            return base
        refs = self.references.get(name)
        if not refs:
            return base
        if len(refs) == 1:
            (ref,) = refs
            hfact = heap.get(ref)
            return join_facts(base, hfact) if hfact else base
        return join_facts(base, *(heap[ref] for ref in refs if ref in heap))

    def copy(self):
        clone = _State.__new__(_State)
        dict.__init__(clone, self)
        clone.bindings = self.bindings.copy()
        clone.references = self.references.copy()
        clone.heap = self.heap.copy()
        clone.mutated = self.mutated.copy()
        clone.cells = self.cells.copy() if self.cells is not None else None
        clone.global_writes = self.global_writes.copy() if self.global_writes is not None else None
        clone.deleted_globals = self.deleted_globals
        clone.maybe_unbound = self.maybe_unbound
        clone.reachable = self.reachable
        return clone

    def replace(self, other):
        if other is None:
            self.reachable = False
            return
        self.clear()
        self.update(other)
        self.bindings = other.bindings.copy()
        self.references = other.references.copy()
        self.heap = other.heap.copy()
        self.mutated = other.mutated.copy()
        self.cells = other.cells.copy() if other.cells is not None else None
        self.global_writes = other.global_writes.copy() if other.global_writes is not None else None
        self.deleted_globals = other.deleted_globals
        self.maybe_unbound = other.maybe_unbound
        self.reachable = other.reachable

    def __eq__(self, other):
        return (isinstance(other, _State) and dict.__eq__(self, other)
                and self.bindings == other.bindings and self.references == other.references
                and self.heap == other.heap and self.mutated == other.mutated
                and self.cells == other.cells
                and self.global_writes == other.global_writes
                and self.deleted_globals == other.deleted_globals
                and self.maybe_unbound == other.maybe_unbound
                and self.reachable == other.reachable)

    def __ne__(self, other):
        # dict implements its own inequality, which otherwise compares only
        # value facts and bypasses our equality. A changed callable, heap or
        # alias must invalidate summaries even when scalar taint is unchanged.
        return not self == other


def _namespace_presence(state, name):
    """Mapping membership is independent from an opaque or None value."""
    marker = state.bindings.get('@presence:' + name, _MISSING)
    if marker is not _MISSING:
        choices = _binding_choices(marker)
        if choices == {_NAMESPACE_PRESENT}:
            return _NAMESPACE_PRESENT
        if choices == {_NAMESPACE_ABSENT}:
            return _NAMESPACE_ABSENT
        return _NAMESPACE_MAYBE
    source = '@global:' + name if '@global:' + name in state.bindings else name
    if name in state.deleted_globals or source in state.maybe_unbound:
        return _NAMESPACE_MAYBE
    return _NAMESPACE_PRESENT if source in state.bindings else _NAMESPACE_ABSENT


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
    if not others:
        clone = first.copy()
        for name, binding in clone.bindings.items():
            if type(binding) is frozenset and len(binding) == 1:  # ubs:ignore[py.comparison.type-equality,py.type-equality]
                clone.bindings[name] = next(iter(binding))
        return clone
    values = first.copy()
    maybe_unbound = set(values.maybe_unbound)
    heap = values.heap
    references = values.references
    for other in others:
        for key, fact in other.items():
            previous = values.get(key, _MISSING)
            if previous is _MISSING:
                values[key] = fact
            elif previous is not fact:
                values[key] = join_facts(previous, fact)
        if other.heap:
            for key, fact in other.heap.items():
                previous = heap.get(key, _MISSING)
                if previous is _MISSING:
                    heap[key] = fact
                elif previous is not fact:
                    heap[key] = join_facts(previous, fact)
        for key, refs in other.references.items():
            previous = references.get(key, _MISSING)
            if previous is _MISSING:
                references[key] = frozenset(refs) if type(refs) is not frozenset else refs  # ubs:ignore[py.comparison.type-equality,py.type-equality]
            elif previous is not refs:
                references[key] = previous | refs
        if other.mutated:
            values.mutated.update(other.mutated)
        values.deleted_globals = values.deleted_globals | other.deleted_globals
        maybe_unbound.update(other.maybe_unbound)
        if other.cells is not None:
            if values.cells is None:
                values.cells = other.cells.copy()
            else:
                cells = values.cells
                for name, ref in other.cells.names.items():
                    previous = cells.names.get(name, ref)
                    if previous != ref:
                        raise AnalysisLimit('ambiguous lexical cell ownership; analysis is incomplete')
                    cells.names[name] = ref
                for ref, contents in other.cells.contents.items():
                    previous = cells.contents.get(ref)
                    cells.contents[ref] = contents if previous is None else _join_cells(previous, contents)
                cells.written.update(other.cells.written)
                cells.multiple.update(other.cells.multiple)
    # A missing binding is not neutral: it stands for the name's implicit
    # identity, so bindings are joined over the full key union as before.
    if len(others) == 1:
        bindings = values.bindings
        first_len = len(bindings)
        second = others[0].bindings
        matched = 0
        for name, other in second.items():
            binding = bindings.get(name, _MISSING)
            if binding is _MISSING:
                bindings[name] = _join_bindings(_implicit_identity(name), other)
                maybe_unbound.add(name)
            elif binding is other:
                matched += 1
                if type(binding) is frozenset and len(binding) == 1:  # ubs:ignore[py.comparison.type-equality,py.type-equality]
                    bindings[name] = next(iter(binding))
            else:
                matched += 1
                bindings[name] = _join_bindings(binding, other)
        if matched != first_len:
            for name, binding in list(bindings.items()):
                if name not in second:
                    bindings[name] = _join_bindings(binding, _implicit_identity(name))
                    maybe_unbound.add(name)
    else:
        bindings = {}
        for name in set(first.bindings).union(*(state.bindings for state in others)):
            bindings[name] = _join_bindings(*(
                state.bindings[name] if name in state.bindings else _implicit_identity(name)
                for state in reachable))
            if any(name not in state.bindings for state in reachable):
                maybe_unbound.add(name)
        values.bindings = bindings
    values.maybe_unbound = frozenset(maybe_unbound)
    if any(state.global_writes for state in reachable):
        changes = {}
        for state in reachable:
            for name, write in (state.global_writes or {}).items():
                previous = changes.get(name)
                changes[name] = write if previous is None else _GlobalWrite(
                    _join_cells(previous.initial, write.initial), previous.current,
                    previous.raw_global and write.raw_global)
        for name, write in changes.items():
            contents = None
            slot = '@global:' + name
            for state in reachable:
                branch = (state.global_writes or {}).get(name)
                if branch is not None:
                    incoming = branch.current
                elif name in state.deleted_globals:
                    incoming = _CellContents(bound=False)
                elif slot in state.bindings or write.raw_global and name in state.bindings:
                    # A module branch can assign directly without ever calling
                    # a setter. Its current value, not the sibling's old entry
                    # snapshot, is the unwritten side of this call effect.
                    key = slot if slot in state.bindings else name
                    presence = _namespace_presence(state, name)
                    incoming = _CellContents(state.get(key, CLEAN),
                                             state.references.get(key, NO_REFERENCES), state.bindings[key],
                                             True if presence == _NAMESPACE_PRESENT else
                                             False if presence == _NAMESPACE_ABSENT else None)
                else:
                    incoming = write.initial
                contents = incoming if contents is None else _join_cells(contents, incoming)
            if contents.bound is not True:
                raise AnalysisLimit('conditional global creation or deletion; analysis is incomplete')
            changes[name] = _GlobalWrite(write.initial, contents, write.raw_global)
            values[slot] = contents.fact
            values.bindings[slot] = contents.binding
            values.references[slot] = contents.references
            values.bindings['@presence:' + name] = _NAMESPACE_PRESENT
            values.maybe_unbound = values.maybe_unbound - {slot, '@presence:' + name}
            if write.raw_global:
                values.maybe_unbound = values.maybe_unbound - {name}
        values.global_writes = changes
    return values


def _same_dict_identity(prev_d, cur_d):
    return (len(prev_d) == len(cur_d)
            and all(map(operator.is_, prev_d.values(), cur_d.values()))
            and all(map(operator.eq, prev_d, cur_d)))


def _identity_snapshot(state):
    """The exact objects a state holds, for a join that would change nothing.

    The tuples keep every value alive, so identity comparison stays sound.
    """
    return (tuple(state), tuple(state.values()),
            tuple(state.bindings), tuple(state.bindings.values()),
            tuple(state.references), tuple(state.references.values()),
            tuple(state.heap), tuple(state.heap.values()),
            frozenset(state.mutated),
            (tuple(state.cells.names.items()), tuple(state.cells.contents), tuple(state.cells.contents.values()),
             frozenset(state.cells.written), frozenset(state.cells.multiple)) if state.cells is not None else None,
            (tuple(state.global_writes), tuple(state.global_writes.values()))
            if state.global_writes is not None else None, state.deleted_globals, state.maybe_unbound)


def _same_snapshot(left, right):
    # Keys compare by equality; values must be the very same objects, since
    # equal facts may still carry different (shorter) evidence paths.
    cells_equal = (left[9] is right[9] or left[9] is not None and right[9] is not None
                   and left[9][:2] == right[9][:2] and left[9][3:] == right[9][3:]
                   and all(map(operator.is_, left[9][2], right[9][2])))
    globals_equal = (left[10] is right[10] or left[10] is not None and right[10] is not None
                     and left[10][0] == right[10][0]
                     and all(map(operator.is_, left[10][1], right[10][1])))
    return (cells_equal and globals_equal and left[11] == right[11] and left[12] == right[12]
            and left[0] == right[0] and left[2] == right[2] and left[4] == right[4]
            and left[6] == right[6] and left[8] == right[8]
            and all(map(operator.is_, left[1], right[1]))
            and all(map(operator.is_, left[3], right[3]))
            and all(map(operator.is_, left[5], right[5]))
            and all(map(operator.is_, left[7], right[7])))


def _same_witness(left, right):
    """Compare immutable analysis values including non-lattice evidence.

    Literal/import bindings are freshly allocated by module evaluation, so
    identity alone would invalidate every cached pass containing constants.
    Structured bindings can contain facts several layers down, however, and
    their ordinary equality deliberately omits the trace's evidence path.
    """
    return _same_analysis_value(left, right, witness=True)


def _same_namespace(left, right):
    if left is right:
        return True
    if left != right:
        return False
    # State equality already covers reference sets, reachability and mutated
    # identities. Only values, heap cells and bindings can carry evidence.
    return ((left.cells is None or all(_same_witness(value, right.cells.contents[ref])
                                      for ref, value in left.cells.contents.items()))
            and (left.global_writes is None or all(_same_witness(value, right.global_writes[name])
                                                   for name, value in left.global_writes.items()))
            and all(_same_witness(value, other[name])
               for values, other in ((left, right), (left.heap, right.heap),
                                     (left.bindings, right.bindings))
               for name, value in values.items()))


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
        # HTTP names are not legacy implicit identities. Once a real import
        # is absent or shadowed, spelling alone cannot restore a network API.
        if node.id in {'requests', 'httpx'}:
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


def _local_names(scope, nodes=None) -> set[str]:
    if nodes is None:
        nodes = tuple(_scope_nodes(scope))
    names = set()
    # Iteration targets belong to the comprehension, not its containing
    # function/module. Walrus targets still belong to the containing scope.
    comprehension_targets = {
        child for node in nodes
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
        for generator in node.generators for child in ast.walk(generator.target)
    }
    for node in nodes:
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
        for node in nodes:
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                names.difference_update(node.names)
    return names


def _direct_global_reads_only(scope):
    """Whether executing a scope can read only its lexical global names.

    This positive whitelist excludes calls and protocol dispatch. Nested
    function bodies are deferred, but their defaults and annotations execute
    now; decorators and type parameters keep the ordinary broad context.
    """
    if isinstance(scope, ast.AsyncFunctionDef):
        return False
    pending = [scope.body] if isinstance(scope, ast.Lambda) else list(scope.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.Name, ast.Constant, ast.Pass, ast.Global, ast.Nonlocal)):
            continue
        if isinstance(node, (ast.Return, ast.Expr)):
            if node.value is not None:
                pending.append(node.value)
        elif isinstance(node, ast.Assign):
            if not all(isinstance(target, ast.Name) for target in node.targets):
                return False
            pending.append(node.value)
        elif isinstance(node, (ast.List, ast.Tuple)):
            if not isinstance(node.ctx, ast.Load):
                return False
            pending.extend(node.elts)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if getattr(node, 'decorator_list', ()) or getattr(node, 'type_params', ()):
                return False
            args = node.args
            pending.extend(args.defaults)
            pending.extend(value for value in args.kw_defaults if value is not None)
            params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
            params.extend(arg for arg in (args.vararg, args.kwarg) if arg is not None)
            pending.extend(arg.annotation for arg in params if arg.annotation is not None)
            if getattr(node, 'returns', None) is not None:
                pending.append(node.returns)
        else:
            return False
    return True


def _used_names(scope, scope_nodes=None) -> set[str]:
    names = set()
    if scope_nodes is None:
        scope_nodes = list(_scope_nodes(scope))
    nodes = list(scope_nodes)
    idx = 0
    while idx < len(nodes):
        node = nodes[idx]
        idx += 1
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
            for child in (*node.decorator_list, *node.args.defaults,
                          *(d for d in node.args.kw_defaults if d is not None)):
                nodes.extend(ast.walk(child))
            for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                        *(a for a in (node.args.vararg, node.args.kwarg) if a is not None)):
                if arg.annotation is not None:
                    nodes.extend(ast.walk(arg.annotation))
            if node.returns is not None:
                nodes.extend(ast.walk(node.returns))
        elif isinstance(node, ast.Lambda):
            for child in (*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)):
                nodes.extend(ast.walk(child))
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
            for child in ast.iter_child_nodes(node):
                nodes.extend(ast.walk(child))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
        elif (capture := _pattern_capture(node)) is not None:
            names.add(capture)
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        args = scope.args
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs,
                    *(a for a in (args.vararg, args.kwarg) if a is not None)):
            names.add(arg.arg)
            if arg.annotation is not None:
                for sub in ast.walk(arg.annotation):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                        names.update(re.findall(r'[A-Za-z_]\w*', sub.value))
                    elif isinstance(sub, ast.Name):
                        names.add(sub.id)
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
    cells: tuple = ()
    multiple_cells: frozenset = frozenset()
    global_writes: tuple = ()


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
    # An exhausted body cannot certify a clean or nonreturning call. Its
    # callers retain opaque-call provenance and the scan stays incomplete.
    incomplete: bool = False
    # Module identity matters: same-spelled globals in two files are distinct.
    capture_globals: frozenset[tuple[ast.Module, str]] = frozenset()
    # Request value identities only when a program/option/argv operation needs
    # them. Ordinary data and unrelated defaults share the same summary.
    value_parameters: frozenset[str] = frozenset()
    # Final contents of written incoming cells and newly escaping cells.
    # Unlike object mutations, these may replace a value or delete its name.
    cells: tuple = ()
    multiple_cells: frozenset = frozenset()
    # (defining module, name, final contents), separate from object mutation.
    global_writes: tuple = ()


class _CallSubstitution:
    """Reuse immutable trace expansions within one call's summary projection."""

    CACHE_LIMIT = 256

    def __init__(self, transform, bound, call_name, budget):
        self.transform = transform
        self.bound = bound
        self.call_name = call_name
        self.budget = budget
        self.cache = {}

    def __call__(self, fact):
        if not fact:
            return CLEAN
        # A cache hit saves computation, never analysis work accounting. Charge
        # the same expansion before consulting the cache, including empty binds.
        self.budget.spend(len(fact) + sum(len(self.bound.get(trace.parameter, CLEAN))
                                        for trace in fact if trace.parameter is not None))
        incoming_facts = []
        for trace in fact:
            if trace.parameter is None:
                incoming_facts.append(frozenset({trace}))
                continue
            actual = self.bound.get(trace.parameter, CLEAN)
            # Lattice equality deliberately omits witnesses. Key every formal
            # field and retain the immutable actual fact with its identity: a
            # changed argument or evidence path cannot reuse an earlier result,
            # even if a caller changes the same bound mapping in place.
            key = (trace.source, trace.parameter, trace.sanitizers, trace.path,
                   id(actual), PATH_LIMIT)
            cached = self.cache.get(key)
            if cached is None:
                incoming = self.transform(trace, actual, self.call_name)
                # Stop admission at a fixed size. The cache dies with this call;
                # long summaries still expand every remaining trace normally.
                if len(self.cache) < self.CACHE_LIMIT:
                    self.cache[key] = (actual, incoming)
            else:
                incoming = cached[1]
            incoming_facts.append(incoming)
        return join_facts(*incoming_facts)


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
        # Return completions may be replaced by finally or discarded while a
        # capture unwinds. Keep only their immutable observations for recovery
        # after a work limit; completed summaries still use the real exits.
        self.observed_returns = []
        self.observed_return_bindings = []
        self.observed_raises = []
        self.yielded_references = set()
        self.returned_bindings = []
        self.yielded_bindings = []
        self.yielded_state = None
        self.generator_return_bindings = {}
        self.normal_state = None
        self.last_state = None
        # Bound exact literal expansion across nested comprehensions. Once
        # exhausted, the finite-lattice loop still analyzes every possible
        # element/effect; this is a precision budget, not a scan cutoff.
        self.comprehension_budget = 64
        self.comprehension_environments = []
        self.class_environments = []
        self.context_globals = ()
        self.capture_globals = set()
        self.value_parameters = set()
        self.observed_global_writes = None
        self.deferred_generator_depth = 0
        self.materialized_generator_depth = 0

    def refine_url_guard(self, test, state, truth):
        """Recognize an exact, terminating local URL allow-list predicate.

        A helper's name is never a sanitizer. Its body must parse the tested
        argument with the resolved stdlib urlparse and require both HTTPS and
        membership in a literal host set that cannot be mutated or escape.
        Only the successful branch receives the SSRF-specific fact.
        """
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.refine_url_guard(test.operand, state, not truth)
        if not (truth and isinstance(test, ast.Call) and len(test.args) == 1
                and not test.keywords and isinstance(test.args[0], ast.Name)):
            return
        choices = _binding_choices(self.expression_bindings.get(test.func))
        if len(choices) != 1:
            return
        function = next(iter(choices))
        if (not isinstance(function, ast.FunctionDef) or function.decorator_list
                or function not in self.engine.functions):
            return
        args = function.args
        parameters = [*args.posonlyargs, *args.args]
        if (len(parameters) != 1 or args.vararg or args.kwarg or args.kwonlyargs
                or args.defaults):
            return
        parameter = parameters[0].arg
        body = list(function.body)
        if body and isinstance(body[0], ast.If):
            guard = body.pop(0)
            if not (isinstance(guard.test, ast.UnaryOp) and isinstance(guard.test.op, ast.Not)
                    and isinstance(guard.test.operand, ast.Name) and guard.test.operand.id == parameter
                    and not guard.orelse and len(guard.body) == 1
                    and isinstance(guard.body[0], ast.Return)
                    and isinstance(guard.body[0].value, ast.Constant)
                    and guard.body[0].value.value is False):
                return
        if not (len(body) == 2 and isinstance(body[0], ast.Assign)
                and len(body[0].targets) == 1 and isinstance(body[0].targets[0], ast.Name)
                and isinstance(body[1], ast.Return)):
            return
        parsed = body[0].targets[0].id
        parser = body[0].value
        if not (parsed != parameter and isinstance(parser, ast.Call)
                and isinstance(parser.func, ast.Name) and parser.func.id not in {parsed, parameter}
                and _qualified(parser.func, self.engine.globals.bindings) == 'urllib.parse.urlparse'
                and len(parser.args) == 1 and not parser.keywords
                and isinstance(parser.args[0], ast.Name) and parser.args[0].id == parameter):
            return
        # The predicate reads its defining module. A caller's compact state
        # may omit urlparse when it only calls this predicate indirectly.
        # Resolve that global exactly as a normal call does, retaining any
        # active rebinding, mutation or unknown closure rather than blessing
        # the spelling of the parser.
        parser_name = parser.func.id
        if (parser_name in self.engine.locals[function]
                or parser_name in self.engine.closures[function]):
            return
        parser_binding = next((value for key, _, _, value in self.global_arguments(function, state)
                               if key == '@global:' + parser_name), None)
        if parser_binding != 'urllib.parse.urlparse':
            return
        condition = body[1].value
        if not (isinstance(condition, ast.BoolOp) and isinstance(condition.op, ast.And)
                and len(condition.values) == 2):
            return
        checked = set()
        for comparison in condition.values:
            if not (isinstance(comparison, ast.Compare) and len(comparison.ops) == 1
                    and isinstance(comparison.left, ast.Attribute)
                    and isinstance(comparison.left.value, ast.Name)
                    and comparison.left.value.id == parsed):
                return
            operand = comparison.comparators[0]
            if (comparison.left.attr == 'scheme' and isinstance(comparison.ops[0], ast.Eq)
                    and isinstance(operand, ast.Constant) and operand.value == 'https'):
                checked.add('scheme')
            elif (comparison.left.attr == 'hostname' and isinstance(comparison.ops[0], ast.In)
                    and isinstance(operand, ast.Name) and operand.id in self.engine.url_allowlists
                    and operand.id not in {parsed, parameter}):
                checked.add('hostname')
            else:
                return
        name = test.args[0].id
        # Do not certify a mutable object's heap or unrelated aliases. A later
        # assignment or heap mutation still introduces its unsanitized facts.
        if checked == {'scheme', 'hostname'} and not any(
                state.heap.get(ref, CLEAN) for ref in state.references.get(name, NO_REFERENCES)):
            self.write_name(state, name, _sanitize(state.value(name), 'ssrf'), state.bindings.get(name),
                            state.references.get(name, NO_REFERENCES), global_write=False)

    def possible_exception(self, state):
        if not (state.reachable and self.exception_states):
            return
        # Most expressions leave the state untouched, and joining the same
        # state twice is idempotent: skip the join when this collector's last
        # joined input holds exactly the same objects. The snapshot retains
        # those objects, including their evidence, independently of mutation
        # of the live input state.
        accumulated = self.exception_states[-1]
        if (state.cells is not None or state.global_writes is not None or state.deleted_globals
                or accumulated is not None and (accumulated.cells is not None
                    or accumulated.global_writes is not None or accumulated.deleted_globals)):
            # The scalar delta below does not represent lexical-cell stores
            # or the initial/current pair of a global write. Joining only
            # visible names can retain a later clean @global slot or an old
            # closure cell and erase a reachable exceptional taint path.
            # Use the complete state join for these namespaces, retaining
            # the same no-op shortcut with a snapshot of every state channel.
            snapshot = _identity_snapshot(state)
            previous = getattr(accumulated, 'last_namespace_join', None)
            if previous is not None and _same_snapshot(previous, snapshot):
                return
            joined = _join_states(accumulated, state)
            joined.last_namespace_join = snapshot
            self.exception_states[-1] = joined
            return
        previous = getattr(accumulated, 'last_joined', None)
        if previous is None:
            joined = _join_states(accumulated, state)
            joined.last_joined = (
                dict(state),
                state.bindings.copy(),
                state.references.copy(),
                state.heap.copy(),
                frozenset(state.mutated),
                state.maybe_unbound,
            )
            self.exception_states[-1] = joined
            return
        prev_vals, prev_bindings, prev_refs, prev_heap, prev_mutated, prev_unbound = previous
        same_vals = _same_dict_identity(prev_vals, state)
        same_bindings = _same_dict_identity(prev_bindings, state.bindings)
        same_refs = _same_dict_identity(prev_refs, state.references)
        same_heap = _same_dict_identity(prev_heap, state.heap)
        same_mutated = (len(prev_mutated) == len(state.mutated) and prev_mutated == state.mutated)
        if (same_vals and same_bindings and same_refs and same_heap and same_mutated
                and prev_unbound == state.maybe_unbound):
            return
        # This collector is owned exclusively by its active capture; it
        # is exposed as a completion only after being popped. Its state
        # already includes every entry in the previous input, so unchanged
        # entries add nothing. Merge the delta in place instead of copying
        # and re-joining the complete namespace at every raising expression.
        joined = accumulated
        if not same_vals:
            for name, fact in state.items():
                if prev_vals.get(name, _MISSING) is fact:
                    continue
                joined_fact = joined.get(name, _MISSING)
                joined[name] = fact if joined_fact is _MISSING else join_facts(joined_fact, fact)
            prev_vals = dict(state)
        if not same_heap:
            heap = joined.heap
            for name, fact in state.heap.items():
                if prev_heap.get(name, _MISSING) is fact:
                    continue
                joined_fact = heap.get(name, _MISSING)
                heap[name] = fact if joined_fact is _MISSING else join_facts(joined_fact, fact)
            prev_heap = state.heap.copy()
        if not same_refs:
            for name, refs in state.references.items():
                if prev_refs.get(name, _MISSING) is not refs:
                    joined.references[name] = joined.references.get(name, NO_REFERENCES) | refs
            prev_refs = state.references.copy()
        if not same_bindings:
            for name, binding in state.bindings.items():
                if prev_bindings.get(name, _MISSING) is not binding:
                    if name not in joined.bindings:
                        joined.maybe_unbound = joined.maybe_unbound | {name}
                    joined.bindings[name] = _join_bindings(
                        joined.bindings.get(name, _implicit_identity(name)), binding)
            # Unlike a missing fact/reference, a missing callable binding
            # contributes the implicit builtin identity. Deletions must
            # join it even though absent keys do not appear in the input.
            if len(prev_bindings) > len(state.bindings) or prev_bindings.keys() != state.bindings.keys():
                for name in prev_bindings.keys() - state.bindings.keys():
                    joined.bindings[name] = _join_bindings(joined.bindings[name], _implicit_identity(name))
                    joined.maybe_unbound = joined.maybe_unbound | {name}
            prev_bindings = state.bindings.copy()
        if not same_mutated:
            joined.mutated.update(state.mutated)
            prev_mutated = frozenset(state.mutated)
        joined.maybe_unbound = joined.maybe_unbound | state.maybe_unbound
        joined.last_joined = (prev_vals, prev_bindings, prev_refs, prev_heap, prev_mutated, state.maybe_unbound)
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
                    self.write_name(branch, handler.name, _advance(item.value, handler.name),
                                    '@exception:' + item.exception_type if item.exception_type else None,
                                    item.references)
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
                            self.write_name(target, handler.name, CLEAN, None, bound=False)
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

    def escape_literal_mapping(self, binding, references, state):
        """Heap aggregates do not retain a nested mapping's ownership graph."""
        for value in _binding_choices(binding):
            if isinstance(value, _LiteralMapping):
                self.mutate(references, CLEAN, state)
            elif isinstance(value, _BoundCallable) and value.name == _LITERAL_MAPPING_GET:
                self.mutate(value.references, CLEAN, state)

    def literal_mapping_contents(self, fact, references, state):
        # A summarized getter and a separate parameter can alias the same
        # dictionary. Until their alias relation is instantiated, a write to
        # either symbolic receiver must remain a possible mapping mutation.
        changed = (frozenset(ref for ref in state.mutated if isinstance(ref, str))
                   if any(isinstance(ref, str) for ref in references)
                   else references & state.mutated)
        self.engine.budget.spend(len(changed))
        return join_facts(fact, *(state.heap.get(ref, CLEAN) for ref in changed)), not changed

    def literal_mapping_key(self, node, state):
        # Hashing/equality on an arbitrary key can run user code and mutate
        # this mapping. Only primitive identities permit a clean selection;
        # callers specialize symbolic keys through the existing finite value
        # contexts rather than assuming every request-derived object is str.
        self.require_value(self.expression_bindings.get(node))
        return self.materialized_generator_hashable(node, state)

    def effect(self, kind, node, label, fact):
        unsafe = frozenset(trace for trace in fact if not _safe_for(trace, kind, label))
        key = (kind, node.lineno, node.col_offset + 1, label)
        if unsafe:
            self.effects[key] = join_facts(self.effects.get(key, CLEAN), unsafe)

    def global_shadowed(self, name):
        if name in (self.engine.locals.get(self.scope, ()) if not isinstance(self.scope, ast.Module) else ()):
            return True
        if name in self.engine.closures.get(self.scope, ()):
            return True
        if any(name in self.engine.locals[scope] for scope, _outer in self.comprehension_environments):
            return True
        return any(name in _local_names(scope) for scope, _outer in self.class_environments)

    def global_contents(self, name, state):
        if name in state.deleted_globals:
            return _CellContents(bound=False)
        namespace, source = self.global_namespace(name, state)
        presence = _namespace_presence(state if '@presence:' + name in state.bindings else namespace, name)
        bound = True if presence == _NAMESPACE_PRESENT else False if presence == _NAMESPACE_ABSENT else None
        if source in namespace.bindings:
            return _CellContents(namespace.get(source, CLEAN), namespace.references.get(source, NO_REFERENCES),
                                 namespace.bindings[source], bound)
        if isinstance(self.scope, ast.Module):
            return _CellContents(bound=False)
        fact, refs, _binding = self.engine.global_symbols[name]
        return _CellContents(fact, refs, self.engine.globals.bindings.get(name), bound)

    def global_namespace(self, name, state):
        """Find the module slot without borrowing class or lexical shadows."""
        slot = '@global:' + name
        if slot in state.bindings:
            return state, slot
        namespace = self.class_environments[0][1] if self.class_environments else state
        if not self.class_environments:
            for scope, outer in self.comprehension_environments:
                if name in self.engine.locals[scope]:
                    namespace = outer
                    break
        local = (self.engine.locals.get(self.scope, frozenset()) | self.engine.closures.get(self.scope, frozenset())
                 if not isinstance(self.scope, ast.Module) else frozenset())
        if not isinstance(self.scope, ast.Module) and (name in local or name not in namespace.bindings):
            namespace = self.engine.globals
        return namespace, slot if slot in namespace.bindings else name

    def put_global(self, name, contents, state):
        """Replace one same-module global without touching a caller's local."""
        if self.deferred_generator_depth:
            raise AnalysisLimit('generator expression global writes require resume-state analysis; '
                                'analysis is incomplete')
        if name not in self.engine.global_names:
            raise AnalysisLimit('new global declaration in a helper; analysis is incomplete')
        if contents.bound is not True:
            raise AnalysisLimit('global deletion requires namespace lifetime analysis; analysis is incomplete')
        if any(name in _local_names(scope) for scope, _outer in self.class_environments):
            # Class bodies resolve a name through their partially constructed
            # namespace before globals. Tracking only lexical assignment sites
            # cannot distinguish a later class binding from an existing one.
            raise AnalysisLimit('global write shadowed by an active class namespace; analysis is incomplete')
        self.engine.budget.spend(1 + len(contents.fact) + len(contents.references))
        initial = self.global_contents(name, state)
        if (self.materialized_generator_depth and initial.bound is not False
                and not self.materialized_generator_binding(initial.binding, initial.references, state)):
            raise AnalysisLimit('generator materialization releases an opaque global; analysis is incomplete')
        if state.global_writes is None:
            state.global_writes = {}
        previous = state.global_writes.get(name)
        state.global_writes[name] = _GlobalWrite(previous.initial if previous else initial, contents,
                                                not self.global_shadowed(name))
        state.deleted_globals = state.deleted_globals - {name}
        if self.observed_global_writes is None:
            self.observed_global_writes = {}
        observed = self.observed_global_writes.get(name)
        self.observed_global_writes[name] = contents if observed is None else _join_cells(observed, contents)
        slot = '@global:' + name
        state[slot], state.references[slot], state.bindings[slot] = (
            contents.fact, contents.references, contents.binding)
        state.bindings['@presence:' + name] = _NAMESPACE_PRESENT
        state.maybe_unbound = state.maybe_unbound - {slot, '@presence:' + name}
        if not self.global_shadowed(name):
            state[name], state.references[name], state.bindings[name] = (
                contents.fact, contents.references, contents.binding)
            state.maybe_unbound = state.maybe_unbound - {name}
        if not isinstance(self.scope, ast.Module):
            # A conditional write may retain the incoming identity. Request
            # that finite context through intermediaries, just like a read.
            self.capture_globals.add((self.engine.tree, name))

    def write_name(self, state, name, fact, binding, references=NO_REFERENCES, *, bound=True,
                   global_write=True):
        """A scalar rebinding replaces a cell; object writes still use mutate."""
        if (self.materialized_generator_depth
                and not any(name in self.engine.locals[scope] for scope, _outer in self.comprehension_environments)):
            if state.cells is not None and name in state.cells.names:
                previous = self.cell_contents(state.cells.names[name], state)
            else:
                previous = _CellContents(state.get(name, CLEAN), state.references.get(name, NO_REFERENCES),
                                         state.bindings.get(name), name in state)
            if (previous.bound is not False
                    and not self.materialized_generator_binding(previous.binding, previous.references, state)):
                raise AnalysisLimit('generator materialization releases an opaque binding; analysis is incomplete')
        declared = name in self.engine.declared_globals.get(self.scope, ())
        module_replacement = (isinstance(self.scope, ast.Module)
                              and '@global:' + name in state.bindings)
        if (global_write and self.deferred_generator_depth and not self.class_environments
                and (declared or isinstance(self.scope, ast.Module))
                and not self.global_shadowed(name)):
            raise AnalysisLimit('generator expression global writes require resume-state analysis; '
                                'analysis is incomplete')
        if (global_write and (declared or module_replacement)
                and not self.class_environments
                and not any(name in self.engine.locals[scope] for scope, _outer in self.comprehension_environments)):
            self.put_global(name, _CellContents(fact, references, binding, bound), state)
        if (global_write and isinstance(self.scope, ast.Module) and not self.class_environments
                and not any(name in self.engine.locals[scope] for scope, _outer in self.comprehension_environments)):
            # Ordinary module cleanup remains supported. Only a later join
            # with a helper's replacement needs to distinguish an actual
            # deletion from a global omitted by a function's compact state.
            state.deleted_globals = (state.deleted_globals - {name} if bound
                                     else state.deleted_globals | {name})
        state[name] = fact
        state.bindings[name] = binding
        state.references[name] = references
        state.maybe_unbound = (state.maybe_unbound - {name} if bound is True
                              else state.maybe_unbound | {name})
        if global_write and (declared or isinstance(self.scope, ast.Module) and not self.class_environments
                and not any(name in self.engine.locals[scope] for scope, _outer in self.comprehension_environments)):
            marker = '@presence:' + name
            if marker in state.bindings:
                state.bindings[marker] = _NAMESPACE_PRESENT if bound is True else _NAMESPACE_ABSENT
                state.maybe_unbound = state.maybe_unbound - {marker}
        if state.cells is not None and name in state.cells.names:
            ref = state.cells.names[name]
            self.engine.budget.spend(1 + len(state.cells.names))
            state.put_cell(ref, _CellContents(fact, references, binding, bound), written=True,
                           weak=ref in state.cells.multiple)

    def lexical_cell(self, function, name, state):
        owner = self.engine.cell_owners.get(function, {}).get(name)
        active = owner is self.scope or any(owner is scope for scope, _outer in self.comprehension_environments)
        inherited = self.engine.cell_owners.get(self.scope, {}).get(name) is owner
        if state.cells is not None and name in state.cells.names and (active or inherited):
            return state.cells.names[name]
        if active or inherited:
            for _class, enclosing in reversed(self.class_environments):
                if enclosing.cells is not None and name in enclosing.cells.names:
                    return enclosing.cells.names[name]
        if not active:
            raise AnalysisLimit(f'lexical cell {name!r} has no defining invocation; analysis is incomplete')
        ref = _CellRef(owner, name)
        cells = state.cell_state()
        if ref in cells.contents:
            # A class body has its own namespace, but its methods close over
            # the enclosing function's already allocated cells.
            return ref
        cells.names[name] = ref
        cells.contents[ref] = _CellContents(state.get(name, CLEAN),
                                          state.references.get(name, NO_REFERENCES),
                                          state.bindings.get(name), name in state)
        self.engine.budget.spend()
        return ref

    def cell_contents(self, ref, state):
        contents = state.cells.contents.get(ref) if state.cells is not None else None
        if contents is not None:
            return contents
        # Imported/module callbacks retain their defining module's cells.
        owner = self.engine.owner(ref.owner) if isinstance(ref, _CellRef) else self.engine
        if owner.globals.cells is not None and ref in owner.globals.cells.contents:
            cells = state.cell_state()
            contents = owner.globals.cells.contents[ref]
            if not isinstance(self.scope, ast.Module):
                # A module capture stores concrete object identities, while
                # this function's heap uses symbolic globals. Preserve both
                # representations of every proven alias. The current frame's
                # module index cannot confuse a foreign or same-name local
                # object with the one that was actually captured.
                def project(objects):
                    aliases = set(objects)
                    self.engine.budget.spend(len(objects))
                    for obj in objects:
                        if not isinstance(obj, ast.AST):
                            continue
                        symbolic = self.engine.global_object_aliases.get(obj)
                        if self.engine.reads is not None:
                            self.engine.reads[('global_object_aliases', obj)] = symbolic
                        if symbolic:
                            aliases.update(symbolic)
                    return frozenset(aliases)

                contents = _CellContents(contents.fact, project(contents.references),
                                         self.map_cell_bindings(contents.binding, lambda cell: cell,
                                                                map_objects=project), contents.bound)
            cells.contents[ref] = contents
            if ref in owner.globals.cells.multiple:
                cells.multiple.add(ref)
            self.engine.budget.spend()
            return contents
        raise AnalysisLimit('unavailable captured lexical cell; analysis is incomplete')

    def closure_environment(self, function, state, closure=None):
        if not self.engine.closures.get(function):
            return state
        refs = dict(closure.cells) if closure is not None else {
            name: self.lexical_cell(function, name, state) for name in self.engine.closures[function]}
        captured = _State()
        for name, ref in refs.items():
            contents = self.cell_contents(ref, state)
            fact = join_facts(contents.fact, *(state.heap.get(obj, CLEAN) for obj in contents.references))
            captured[name] = fact
            captured.references[name] = contents.references
            captured.bindings[name] = (_without_object_contract(contents.binding)
                                       if contents.references & state.mutated else contents.binding)
        return captured

    def generator_receiver_proof(self, function):
        """Prove that captured cells only receive monotone builtin-list writes.

        These effects do not read captured data or depend on a resumable cell
        replacement. Every other lexical dependency keeps the explicit
        generator boundary until suspension states are represented.
        """
        captures = self.engine.cell_owners.get(function, {})
        if not captures:
            return False
        seen = set()
        for node in ast.walk(function):
            self.engine.budget.spend()
            if node is not function and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                          ast.Lambda, ast.ClassDef, ast.GeneratorExp)):
                return False
            if not isinstance(node, ast.Name) or node.id not in captures:
                continue
            attribute = self.engine.parents.get(node)
            call = self.engine.parents.get(attribute)
            statement = self.engine.parents.get(call)
            if not (isinstance(node.ctx, ast.Load) and isinstance(attribute, ast.Attribute)
                    and attribute.value is node and attribute.attr in {'append', 'extend', 'insert'}
                    and isinstance(call, ast.Call) and call.func is attribute
                    and isinstance(statement, ast.Expr) and statement.value is call
                    and not call.keywords and not any(isinstance(arg, ast.Starred) for arg in call.args)
                    and len(call.args) == (2 if attribute.attr == 'insert' else 1)):
                return False
            seen.add(node.id)
        if seen != set(captures):
            return False
        for name, defining in captures.items():
            if not isinstance(defining, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return False
            declaration = function
            while self.engine.parents.get(declaration) is not defining:
                declaration = self.engine.parents.get(declaration)
                if declaration is None:
                    return False
            target = None
            for statement in defining.body:
                if statement is declaration:
                    break
                candidate = (statement.targets[0] if isinstance(statement, ast.Assign)
                             and len(statement.targets) == 1 else
                             statement.target if isinstance(statement, ast.AnnAssign) else None)
                if (isinstance(candidate, ast.Name) and candidate.id == name
                        and isinstance(statement.value, ast.List)):
                    target = candidate
            if target is None:
                return False
            # Reject even shadowing writes in descendant scopes: this is a
            # positive proof, not a partial nonlocal/reflective execution model.
            for node in ast.walk(defining):
                self.engine.budget.spend()
                if (isinstance(node, ast.Name) and node.id == name
                        and isinstance(node.ctx, (ast.Store, ast.Del)) and node is not target
                        or isinstance(node, ast.arg) and node.arg == name
                        or isinstance(node, ast.Nonlocal) and name in node.names
                        or isinstance(node, ast.ExceptHandler) and node.name == name
                        or _pattern_capture(node) == name
                        or node is not defining and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                                      ast.ClassDef)) and node.name == name
                        or isinstance(node, (ast.Import, ast.ImportFrom))
                        and any((alias.asname or alias.name.split('.')[0]) == name for alias in node.names)):
                    return False
        return True

    def stable_generator_receivers(self, function, closure, state):
        owner = self.engine.owner(function)
        proven = owner.generator_receiver_proofs.get(function)
        if proven is None:
            proven = self.generator_receiver_proof(function)
            owner.generator_receiver_proofs[function] = proven
        if not proven:
            return False
        for _name, ref in closure.cells:
            contents = self.cell_contents(ref, state)
            if contents.bound is not True or state.cells is not None and ref in state.cells.multiple:
                return False
        return True

    def generator_builtins_stable(self, owner=None):
        engines = (self.engine, owner or self.engine)
        project = self.engine.project
        if project is not None:
            # Ambiguous import keys deliberately map to None. Every selected
            # engine still participates in this namespace proof.
            engines = (engine for _path, _text, engine, _offset in project.sources)
        return all(engine.generator_input_identity for engine in engines)

    def generator_summary_globals(self, summary):
        """Find delayed globals in every immutable summary channel.

        A helper can expose a late read through an object write, exception,
        saved callback or cell without returning that value directly. Walk
        the shared analysis-value DAG, never the source AST or a project.
        """
        names, seen, pending = set(), set(), [summary]
        while pending:
            value = pending.pop()
            if id(value) in seen:
                continue
            seen.add(id(value))
            self.engine.budget.spend()
            if isinstance(value, (TaintTrace, _SymbolicValue)):
                parameter = value.parameter
                if parameter and parameter.startswith('@global:'):
                    names.add(parameter[8:])
            elif isinstance(value, str):
                if value.startswith('@global:'):
                    names.add(value[8:])
            elif isinstance(value, (tuple, frozenset)):
                pending.extend(value)
            elif not isinstance(value, _LiteralString) and is_dataclass(value):
                pending.extend(getattr(value, item.name) for item in fields(value))
        return names

    def generator_exhaustion_consumer(self, node, state):
        """Identify a direct, synchronous builtin consumer before its argument.

        The callable was evaluated before constructing the generator. No
        remaining operand can run between that construction and exhaustion.
        Iterator, callback and value-lifetime proofs belong to the producer.
        """
        original = self.engine.original_calls.get(node, node)
        consumer = self.engine.parents.get(original)
        if (not isinstance(consumer, ast.Call) or consumer.args != [original]
                or consumer.keywords or self.class_environments or self.engine.generator_namespace_exposed
                or self.engine.generator_frame_exposed):
            return False
        method = consumer.func
        string_join = (isinstance(method, ast.Attribute) and method.attr == 'join'
                       and self.materialized_generator_string(method.value, state))
        choices = _binding_choices(self.expression_bindings.get(method))
        if string_join:
            # A bound method of an already evaluated, exact builtin string
            # exhausts its sole argument synchronously. A name ending in
            # "join" or a receiver's old initializer is not that proof.
            names = set()
        else:
            if not choices or not choices <= {
                    'list', 'tuple', 'any', 'all',
                    'builtins.list', 'builtins.tuple', 'builtins.any', 'builtins.all'}:
                return False
            names = {value.rsplit('.', 1)[-1] for value in choices}
            if names & {'any', 'all'}:
                if len(names) != 1:
                    return False  # Different callees do not share an exhaustion policy.
                if self.generator_expression_immediate(node, state):
                    # Keep the existing proof for read-only predicates over
                    # retained collections. Effectful predicates below need
                    # ordered consumption and explicit short-circuit exits.
                    return False
        if not self.generator_consumer_stable(consumer, names):
            return False
        return 'str.join' if string_join else next(iter(names)) if names <= {'any', 'all'} else 'collection'

    def generator_consumer_stable(self, consumer, names):
        """Require native consumer identities without exposed execution state."""
        if (self.class_environments or self.engine.generator_namespace_exposed
                or self.engine.generator_frame_exposed):
            return False
        # An enclosing sink such as eval(next(...)) executes after its
        # argument finishes. A same-line source position does not make that
        # call an intervening namespace mutation during consumption.
        enclosing_calls = set()
        child = self.engine.original_calls.get(consumer, consumer)
        while child in self.engine.parents:
            parent = self.engine.parents[child]
            if isinstance(parent, ast.Call) and parent.func is not child:
                enclosing_calls.add(parent)
            child = parent
        for engine in self.engine.generator_peers:
            if (engine.generator_builtin_reflection or engine.generator_literal_authority_exposed
                    or names & engine.generator_attribute_writes
                    or engine is not self.engine and engine.generator_namespace_exposed):
                return False
            for capability in engine.generator_execution_capabilities:
                call = engine.parents.get(capability)
                spelling = capability.id if isinstance(capability, ast.Name) else capability.attr
                if (engine is not self.engine or spelling == 'exec'
                        or not isinstance(call, ast.Call) or call.func is not capability
                        or self.engine.enclosing(call) is not self.scope
                        or call.lineno <= consumer.end_lineno and call not in enclosing_calls):
                    return False
        return True

    def immediate_next(self, node, state, binding):
        """Capture an iterator, evaluate the default, then resume to one yield.

        Generator construction evaluates only the outer iterable. Consuming
        it while evaluating the first argument would run before the default
        and could observe stale globals, lose prefix writes, or execute a
        body whose default argument raises. Keep those phases explicit.
        """
        if (not node.args or not isinstance(node.args[0], ast.GeneratorExp)
                or len(node.args) not in {1, 2} or node.keywords):
            return _MISSING
        choices = _binding_choices(binding)
        if not choices or not choices <= {'next', 'builtins.next'}:
            return _MISSING
        if isinstance(node.func, ast.Name):
            refs = self.expression_references.get(node.func, NO_REFERENCES)
            if any(not isinstance(ref, str) or not ref.startswith('@global:')
                   or self.engine.globals.references.get(ref[8:], NO_REFERENCES) for ref in refs):
                raise AnalysisLimit('generator next callable capture lifetime is unresolved; analysis is incomplete')
        elif not (isinstance(node.func, ast.Attribute) and node.func.attr == 'next'
                  and isinstance(node.func.value, ast.Name)
                  and node.func.value.id in self.engine.generator_readonly_builtins
                  and self.expression_bindings.get(node.func.value) == 'builtins'):
            raise AnalysisLimit('generator next computed callable lifetime is unresolved; analysis is incomplete')
        if (not self.generator_consumer_stable(node, {'next'})
                or not self.generator_builtins_stable()):
            raise AnalysisLimit('generator next consumer identity is unresolved; analysis is incomplete')
        generator = node.args[0]
        if any(clause.is_async for clause in generator.generators):
            raise AnalysisLimit('asynchronous generator next consumption is unmodeled; analysis is incomplete')
        self.materialized_generator_depth += 1
        try:
            first = generator.generators[0].iter
            iterable = self.expr(first, state)
            if not state.reachable:
                return CLEAN
            if not self.materialized_generator_iterable(first, state):
                raise AnalysisLimit('generator next iterator or captured lifetime is unresolved; analysis is incomplete')
            default = node.args[1] if len(node.args) == 2 else None
            if default is not None:
                self.expr(default, state)
                if not state.reachable:
                    return CLEAN
                if not self.materialized_generator_inert(default, state):
                    raise AnalysisLimit('generator next default lifetime is unresolved; analysis is incomplete')
            # A private outer local keeps its value alive after this cursor
            # is discarded. A direct Name read has no protocol, and next
            # does not test the yielded object's truth. Reuse the existing
            # retained-capture proof only when no clause can replace it.
            borrowed = (isinstance(generator.elt, ast.Name)
                        and generator.elt.id in self.engine.locals.get(self.scope, ())
                        and generator.elt.id not in self.engine.locals[generator]
                        and len(generator.generators) == 1 and not generator.generators[0].ifs
                        and self.generator_expression_immediate(generator, state)
                        and self.engine.generator_stable_binding(
                            generator.elt.id, self.scope, generator, immediate=True))
            fact = self.comprehension(generator, state, iterable=iterable, synchronous_generator=True,
                                      first_result=True, default=default, borrowed_result=borrowed)
            self.expression_bindings[node] = self.expression_bindings.get(generator)
            self.expression_references[node] = self.expression_references.get(generator, NO_REFERENCES)
            return fact
        finally:
            self.materialized_generator_depth -= 1

    def materialized_generator_string(self, node, state):
        """Require the evaluated value to be an exact, callback-free string."""
        references = self.expression_references.get(node, NO_REFERENCES)
        choices = _binding_choices(self.expression_bindings.get(node))
        self.engine.budget.spend(1 + len(choices))
        return (not references & state.mutated and bool(choices)
                and all(isinstance(value, (_LiteralString, _GeneratorString))
                        or isinstance(value, ast.Constant) and type(value.value) is str
                        for value in choices))

    @staticmethod
    def formatted_string_scalar(value):
        # Decimal conversion of a huge exact int can raise ValueError.
        # 2048 bits fit below Python's minimum configurable 640-digit limit,
        # independently of the scanning process's configuration.
        return (type(value) in {str, bytes, float, complex, bool, type(None)}
                or type(value) is int and value.bit_length() <= 2048)

    def formatted_string_operand(self, node, state):
        """Prove both a primitive value and its immediate evaluation lifetime.

        A helper returning a string can still release opaque locals/defaults.
        Likewise, native input can invoke an opaque prompt's __str__. Keep
        those protocols outside the exact-string proof instead of inferring
        safety from the final value's nominal type alone.
        """
        self.engine.budget.spend()

        if isinstance(node, ast.Constant):
            return self.formatted_string_scalar(node.value)
        references = self.expression_references.get(node, NO_REFERENCES)
        choices = _binding_choices(self.expression_bindings.get(node))
        if (references & state.mutated or not choices
                or not all(isinstance(value, (_LiteralString, _GeneratorString)) and value.format_safe
                           or isinstance(value, ast.Constant) and self.formatted_string_scalar(value.value)
                           for value in choices)):
            return False
        if isinstance(node, (ast.Name, ast.JoinedStr)):
            return True
        if isinstance(node, ast.Call):
            callees = _binding_choices(self.expression_bindings.get(node.func))
            return (bool(callees) and callees <= {'input', 'builtins.input'}
                    and len(node.args) <= 1 and not node.keywords
                    and self.generator_builtins_stable()
                    and self.generator_consumer_stable(node, {'input'})
                    and all(self.formatted_string_operand(argument, state) for argument in node.args))
        return False

    def without_format_authority(self, binding):
        """Retain value contracts without certifying an opaque producer frame.

        A helper returning its argument can retain only the argument's object
        references, losing the helper's own finalizers. This separate bit is
        monotone across aliases, alternatives, vectors and summary returns.
        """
        choices = []
        for value in _binding_choices(binding):
            self.engine.budget.spend()
            if isinstance(value, _LiteralString):
                value = _LiteralString(value.value, format_safe=False)
            elif isinstance(value, _GeneratorString):
                value = _GeneratorString(format_safe=False)
            elif isinstance(value, ast.Constant):
                value = None
            elif isinstance(value, _ArgumentVector):
                value = _ArgumentVector(tuple((self.without_format_authority(operand), fact)
                                              for operand, fact in value.operands), value.references)
            choices.append(value)
        return _join_bindings(*choices)

    def formatted_string_spec(self, node, state):
        """Accept only conversions/specs that cannot call user code or fail.

        Empty formatting is valid for every admitted exact scalar. Nonempty
        specs are restricted to the builtin string grammar, after any explicit
        !s/!r/!a conversion. Dynamic specs and numeric presentation need their
        own normal/exceptional completions; they do not acquire this proof.
        No analyzed value is formatted or executed to validate its spec.
        """
        if node.conversion not in {-1, ord('s'), ord('r'), ord('a')}:
            return False
        if node.format_spec is None:
            return True
        if (not isinstance(node.format_spec, ast.JoinedStr)
                or not all(isinstance(value, ast.Constant) and type(value.value) is str
                           for value in node.format_spec.values)):
            return False
        spec = ''.join(value.value for value in node.format_spec.values)
        self.engine.budget.spend(1 + len(spec))
        if not spec:
            return True
        if node.conversion == -1 and not self.materialized_generator_string(node.value, state):
            return False
        match = re.fullmatch(r'(?:(?:.)?[<^>])?(?P<width>[0-9]*)(?:\.(?P<precision>[0-9]+))?s?',
                             spec, re.DOTALL)
        # CPython rejects sizes outside Py_ssize_t before producing a value.
        # Bound digit parsing too; leading zeroes need not expand our proof.
        return (match is not None and all(
            not digits or len(digits) <= 20 and int(digits) <= sys.maxsize
            for digits in match.groups()))

    def materialized_generator_inert(self, node, state):
        """Prove an evaluated operand cannot own an opaque finalizer/protocol.

        Captured identities, not a variable's old initializer, supply type
        evidence. In particular an input-result marker survives a later
        rebinding without reinterpreting its creation AST in the new state.
        """
        self.engine.budget.spend()
        references = self.expression_references.get(node, NO_REFERENCES)
        if references & state.mutated:
            return False
        if isinstance(node, ast.Constant):
            return type(node.value) in {str, bytes, int, float, complex, bool, type(None)}
        if isinstance(node, ast.NamedExpr):
            return self.materialized_generator_inert(node.value, state)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self.materialized_generator_inert(value, state) for value in node.elts)
        if isinstance(node, ast.Dict):
            return all(key is not None and self.materialized_generator_inert(key, state)
                       and self.materialized_generator_inert(value, state)
                       for key, value in zip(node.keys, node.values))
        if isinstance(node, ast.Call):
            # A native prompt/conversion or summarized helper must not invoke
            # an unmodeled protocol on an opaque passed object.
            if (any(isinstance(value, ast.Starred) for value in node.args)
                    or any(keyword.arg is None for keyword in node.keywords)
                    or not all(self.materialized_generator_inert(value, state)
                               for value in (*node.args, *(keyword.value for keyword in node.keywords)))):
                return False
        if isinstance(node, ast.Compare):
            return all(self.materialized_generator_inert(value, state)
                       for value in (node.left, *node.comparators))
        if isinstance(node, ast.BoolOp):
            if node in self.expression_bindings:
                return self.materialized_generator_binding(self.expression_bindings[node], references, state)
            return all(self.materialized_generator_inert(value, state) for value in node.values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.materialized_generator_inert(node.operand, state)
        return self.materialized_generator_binding(self.expression_bindings.get(node), references, state)

    def materialized_generator_binding(self, binding, references, state):
        """Only captured primitive identities certify reference release."""
        choices = _binding_choices(binding)
        if references & state.mutated or not choices:
            return False
        for value in choices:
            self.engine.budget.spend()
            if isinstance(value, (_LiteralString, _GeneratorString)):
                continue
            if (isinstance(value, ast.Constant)
                    and type(value.value) in {str, bytes, int, float, complex, bool, type(None)}):
                continue
            if isinstance(value, _ArgumentVector) and all(
                    self.materialized_generator_binding(operand, value.references_at(index), state)
                    for index, (operand, _fact) in enumerate(value.operands)):
                continue
            return False
        return True

    def materialized_generator_hashable(self, node, state):
        """Inert containers can still fail before iteration during hashing."""
        self.engine.budget.spend()
        if isinstance(node, ast.NamedExpr):
            return self.materialized_generator_hashable(node.value, state)
        if isinstance(node, ast.Tuple):
            return all(self.materialized_generator_hashable(item, state) for item in node.elts)
        if isinstance(node, (ast.List, ast.Set, ast.Dict)):
            return False
        if isinstance(node, ast.Constant):
            return type(node.value) in {str, bytes, int, float, complex, bool, type(None)}
        choices = _binding_choices(self.expression_bindings.get(node))
        return (not any(isinstance(value, _ArgumentVector) for value in choices)
                and self.materialized_generator_binding(self.expression_bindings.get(node),
                    self.expression_references.get(node, NO_REFERENCES), state))

    def materialized_generator_call(self, node, target, state):
        """Prove calls cannot hide owned finalizers, including exceptional exits.

        A primitive return alone says nothing about released locals/defaults.
        Admit native input and a bounded straight-line helper subset whose
        entire frame contains primitive values. General callbacks, defaults,
        argument expansion and nested calls still need an ownership summary.
        """
        self.engine.budget.spend()
        if (any(isinstance(value, ast.Starred) for value in node.args)
                or any(keyword.arg is None for keyword in node.keywords)
                or not all(self.materialized_generator_inert(value, state)
                           for value in (*node.args, *(keyword.value for keyword in node.keywords)))):
            return False
        if target in ('input', 'builtins.input'):
            return (self.generator_builtins_stable() and len(node.args) <= 1 and not node.keywords
                    and all(self.formatted_string_operand(argument, state) for argument in node.args))
        closure = target if isinstance(target, _ClosureValue) else None
        if closure is not None:
            target = closure.value
        if isinstance(target, _FunctionValue):
            target = target.function
        if (not isinstance(target, ast.FunctionDef) or self.engine.owner(target) is not self.engine
                or target in self.engine.generators or target.decorator_list or target.returns is not None
                or not self.engine.generator_helper_identity(target)):
            return False
        signature = target.args
        positional = [*signature.posonlyargs, *signature.args]
        if (signature.vararg or signature.kwarg or signature.defaults
                or any(value is not None for value in signature.kw_defaults)
                or any(argument.annotation is not None for argument in (*positional, *signature.kwonlyargs))
                or len(node.args) > len(positional)):
            return False
        arguments = {argument.arg: value for argument, value in zip(positional, node.args)}
        accepted = {argument.arg for argument in (*signature.args, *signature.kwonlyargs)}
        for keyword in node.keywords:
            if keyword.arg not in accepted or keyword.arg in arguments:
                return False
            arguments[keyword.arg] = keyword.value
        if set(arguments) != {argument.arg for argument in (*positional, *signature.kwonlyargs)}:
            return False
        captured = {}
        for name, ref in closure.cells if closure is not None else ():
            contents = self.cell_contents(ref, state)
            if (contents.bound is not True
                    or not self.materialized_generator_binding(contents.binding, contents.references, state)):
                return False
            captured[name] = contents.binding
        local_names = self.engine.locals.get(target, ())
        values = {name: (expression if isinstance(expression, ast.Constant)
                         else self.expression_bindings.get(expression))
                  for name, expression in arguments.items()}
        # Ownership/hashability alone does not authorize decimal conversion
        # when input() prints a prompt. Keep the evaluated scalar separately
        # from the abstract ownership markers used by this bounded proof.
        prompt_values = values.copy()

        def lookup(name):
            if name in values:
                return values[name]
            if name in local_names:
                return None
            if name in captured:
                return captured[name]
            if name not in self.engine.global_names:
                return _implicit_identity(name)
            contents = self.global_contents(name, state)
            if contents.bound is False and name not in self.engine.global_names:
                return _implicit_identity(name)
            if contents.references & state.mutated:
                return None
            return contents.binding

        def primitive(expression):
            self.engine.budget.spend()
            if isinstance(expression, ast.Constant):
                return type(expression.value) in {str, bytes, int, float, complex, bool, type(None)}
            if isinstance(expression, ast.Name):
                return self.materialized_generator_binding(lookup(expression.id), NO_REFERENCES, state)
            if isinstance(expression, (ast.Tuple, ast.List)):
                return all(primitive(item) for item in expression.elts)
            if isinstance(expression, ast.Set):
                return all(hashable(item) for item in expression.elts)
            if isinstance(expression, ast.Dict):
                return all(key is not None and hashable(key) and primitive(value)
                           for key, value in zip(expression.keys, expression.values))
            if (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name)
                    and lookup(expression.func.id) in ('input', 'builtins.input')
                    and not expression.keywords and len(expression.args) <= 1
                    and self.generator_builtins_stable()):
                return all(prompt(argument) for argument in expression.args)
            return False

        def prompt(expression):
            self.engine.budget.spend()
            if isinstance(expression, ast.Constant):
                return self.formatted_string_scalar(expression.value)
            if isinstance(expression, ast.Name):
                binding = (prompt_values[expression.id] if expression.id in prompt_values
                           else lookup(expression.id))
                choices = _binding_choices(binding)
                return bool(choices) and all(
                    isinstance(value, (_LiteralString, _GeneratorString)) and value.format_safe
                    or isinstance(value, ast.Constant) and self.formatted_string_scalar(value.value)
                    for value in choices)
            return isinstance(expression, ast.Call) and primitive(expression)

        def hashable(expression):
            self.engine.budget.spend()
            if isinstance(expression, ast.Tuple):
                return all(hashable(item) for item in expression.elts)
            if isinstance(expression, (ast.List, ast.Set, ast.Dict)):
                return False
            if isinstance(expression, ast.Name) and any(
                    isinstance(value, _ArgumentVector) for value in _binding_choices(lookup(expression.id))):
                return False
            return primitive(expression)

        def raised(expression):
            if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name):
                identity = lookup(expression.func.id)
                if (not expression.keywords and all(primitive(argument) for argument in expression.args)
                        and isinstance(identity, str) and identity.startswith('builtins.')
                        and self.generator_builtins_stable()):
                    exception = getattr(builtins, identity[9:], None)
                    return isinstance(exception, type) and issubclass(exception, BaseException)
            return False

        for statement in target.body:
            self.engine.budget.spend()
            if isinstance(statement, (ast.Global, ast.Nonlocal, ast.Pass)):
                continue
            if isinstance(statement, ast.Assign) and primitive(statement.value):
                expression = statement.value
                prompt_value = (expression if isinstance(expression, ast.Constant)
                                else prompt_values.get(expression.id, lookup(expression.id))
                                if isinstance(expression, ast.Name)
                                else _GeneratorString() if isinstance(expression, ast.Call) else None)
                for destination in statement.targets:
                    if not isinstance(destination, ast.Name):
                        return False
                    if destination.id not in local_names:
                        # Replacing a borrowed global/cell may release its
                        # last owner even when the new value is just a string.
                        if not self.materialized_generator_binding(lookup(destination.id), NO_REFERENCES, state):
                            return False
                    # The proof environment records ownership/hashability,
                    # not a substitute runtime value. A list alias must not
                    # become a supposedly hashable key on its next use.
                    values[destination.id] = (_GeneratorString() if hashable(statement.value)
                                               else _ArgumentVector(()))
                    prompt_values[destination.id] = prompt_value
                continue
            if isinstance(statement, ast.Expr) and primitive(statement.value):
                continue
            if isinstance(statement, ast.Return):
                return statement.value is None or primitive(statement.value)
            if isinstance(statement, ast.Raise):
                return statement.cause is None and raised(statement.exc)
            return False
        return True

    def materialized_generator_iterable(self, node, state):
        """Only inert builtin collections have modeled iteration and teardown."""
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            return self.materialized_generator_inert(node, state)
        # An evaluated fixed vector retains the actual operands and their
        # aliases. Never recover a mutable collection from stale source text.
        references = self.expression_references.get(node, NO_REFERENCES)
        choices = _binding_choices(self.expression_bindings.get(node))
        if (not references & state.mutated and choices
                and all(isinstance(value, (_LiteralString, _GeneratorString)) for value in choices)):
            return True
        if (not references or references & state.mutated or not choices
                or not all(isinstance(value, _ArgumentVector) for value in choices)):
            return False
        for vector in choices:
            for index, (operand, _fact) in enumerate(vector.operands):
                if vector.references_at(index) & state.mutated:
                    return False
                if not all(isinstance(value, (_LiteralString, _GeneratorString))
                           or isinstance(value, ast.Constant)
                           and type(value.value) in {str, bytes, int, float, complex, bool, type(None)}
                           for value in _binding_choices(operand)):
                    return False
        return True

    def generator_expression_immediate(self, node, state):
        """Bound only private name lifetimes for an exact synchronous predicate."""
        consumer = self.engine.parents.get(node)
        if (not isinstance(consumer, ast.Call) or not consumer.args or consumer.args[0] is not node or consumer.keywords
                or len(node.generators) != 1
                or self.engine.generator_namespace_exposed or self.engine.generator_frame_exposed):
            return False
        choices = _binding_choices(self.expression_bindings.get(consumer.func))
        if not choices or not choices <= {'any', 'all', 'next', 'builtins.any', 'builtins.all', 'builtins.next'}:
            return False
        names = {value.rsplit('.', 1)[-1] for value in choices}
        if len(consumer.args) != 1 and not (names == {'next'} and len(consumer.args) == 2
                                            and isinstance(consumer.args[1], ast.Constant)):
            return False
        for engine in self.engine.generator_peers:
            if (engine.generator_literal_authority_exposed
                    or engine is not self.engine and engine.generator_namespace_exposed):
                return False
            for capability in engine.generator_execution_capabilities:
                call = engine.parents.get(capability)
                spelling = capability.id if isinstance(capability, ast.Name) else capability.attr
                if (engine is not self.engine or spelling == 'exec'
                        or not isinstance(call, ast.Call) or call.func is not capability
                        or self.engine.enclosing(call) is not self.scope or call.lineno <= consumer.end_lineno):
                    return False
        iterable = node.generators[0].iter
        if isinstance(iterable, ast.Constant) and isinstance(iterable.value, (str, bytes)):
            pass  # Exact immutable scalar iteration has no user callbacks.
        elif isinstance(iterable, (ast.List, ast.Tuple, ast.Set)):
            # A temporary iterable must not release opaque captured objects
            # when a predicate short-circuits or next() discards its cursor.
            if not all(isinstance(item, ast.Constant) for item in iterable.elts):
                return False
        elif isinstance(iterable, ast.Name):
            if not self.engine.generator_stable_binding(iterable.id, self.scope, node, immediate=True):
                return False
            refs = state.references.get(iterable.id, NO_REFERENCES)
            if refs == frozenset({'@global:' + iterable.id}):
                refs = self.engine.globals.references.get(iterable.id, NO_REFERENCES)
            # A separate stable binding retains this builtin collection
            # across consumption. Its items need not be classified as inert.
            if not refs or not all(isinstance(ref, (ast.List, ast.Tuple, ast.Set, ast.Dict,
                                                    ast.ListComp, ast.SetComp, ast.DictComp)) for ref in refs):
                return False
            if (not all(isinstance(ref, ast.Tuple) for ref in refs)
                    and not self.engine.generator_collection_retained(iterable.id, self.scope)):
                return False
        else:
            return False  # Arbitrary iterator/attribute protocols remain unresolved.
        if (names != {'next'} and not self.generator_primitive_truth(node.elt, node, state)
                or any(not self.generator_primitive_truth(condition, node, state)
                       for generator in node.generators for condition in generator.ifs)):
            return False
        engines = ((engine for _path, _text, engine, _offset in self.engine.project.sources)
                   if self.engine.project is not None else (self.engine,))
        return not any(names & engine.generator_attribute_writes for engine in engines)

    def generator_primitive_truth(self, expression, generator, state, *, string=False, seen=frozenset()):
        """Prove implicit truth testing cannot invoke an arbitrary object callback."""
        self.engine.budget.spend()
        if isinstance(expression, ast.Constant):
            return isinstance(expression.value, str) if string else type(expression.value) in {
                str, bytes, int, float, complex, bool, type(None)}
        if isinstance(expression, ast.Name):
            if expression.id in seen:
                return False
            seen = seen | {expression.id}
            first = generator.generators[0]
            if expression.id in self.engine.locals[generator]:
                # A comprehension target never inherits a same-spelled
                # enclosing binding, including targets inside unpacking.
                if not isinstance(first.target, ast.Name) or first.target.id != expression.id:
                    return False
                values = first.iter.elts if isinstance(first.iter, (ast.List, ast.Tuple, ast.Set)) else ()
            else:
                bindings = _binding_choices(state.bindings.get(expression.id))
                if bindings and all(isinstance(value, (_LiteralString, _GeneratorString)) for value in bindings):
                    return True
                values = []
                for binder in self.engine.generator_binders.get(self.scope, {}).get(expression.id, ()):
                    parent = self.engine.parents.get(binder)
                    if (isinstance(parent, ast.For) and parent.target is binder
                            and isinstance(parent.iter, (ast.List, ast.Tuple, ast.Set))):
                        values.extend(parent.iter.elts)
                    elif isinstance(parent, (ast.Assign, ast.AnnAssign)) and isinstance(binder, ast.Name):
                        values.append(parent.value)
                    else:
                        return False
            # These operands were evaluated before the capture. A saved
            # alias must not be reinterpreted using its current binding.
            return bool(values) and all(
                isinstance(value, ast.Constant)
                and self.generator_primitive_truth(value, generator, state, string=string, seen=seen)
                or self.generator_primitive_input(value) for value in values)
        if isinstance(expression, ast.Call):
            if self.generator_primitive_input(expression):
                return True
            if (not string and isinstance(expression.func, ast.Attribute)
                    and expression.func.attr in {'startswith', 'endswith'}
                    and not expression.keywords and len(expression.args) == 1):
                return (self.generator_primitive_truth(expression.func.value, generator, state, string=True, seen=seen)
                        and self.generator_primitive_truth(expression.args[0], generator, state, string=True, seen=seen))
        if not string:
            if isinstance(expression, ast.Compare):
                return all(self.generator_primitive_truth(value, generator, state, seen=seen)
                           for value in (expression.left, *expression.comparators))
            if isinstance(expression, ast.BoolOp):
                return all(self.generator_primitive_truth(value, generator, state, seen=seen)
                           for value in expression.values)
            if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
                return self.generator_primitive_truth(expression.operand, generator, state, seen=seen)
        return False

    def generator_primitive_input(self, expression):
        if not isinstance(expression, ast.Call):
            return False
        choices = _binding_choices(self.expression_bindings.get(expression.func))
        return bool(choices and choices <= {'input', 'builtins.input'} and self.generator_builtins_stable())

    def generator_borrowed_capture(self, node, references, state):
        """Prove a direct for-frame does not own a mutable capture's lifetime."""
        original = self.engine.original_calls.get(node, node)
        consumer = self.engine.parents.get(original)
        if (self.scope is not self.engine.tree or not isinstance(consumer, ast.For)
                or self.engine.parents.get(consumer) is not self.engine.tree
                or consumer.iter is not original or len(references) != 1
                or not isinstance(next(iter(references)), ast.List)):
            return False
        engines = ((engine for _path, _text, engine, _offset in self.engine.project.sources)
                   if self.engine.project is not None else (self.engine,))
        for engine in engines:
            for capability in engine.generator_execution_capabilities:
                call = engine.parents.get(capability)
                # A helper or saved eval/exec alias could delete the root
                # during suspension. Only a direct module call strictly
                # after this top-level loop is outside the borrowed lifetime.
                if (engine is not self.engine or not isinstance(call, ast.Call)
                        or call.func is not capability or engine.enclosing(call) is not engine.tree
                        or call.lineno <= consumer.end_lineno):
                    return False
        # The contents need not be inert. A distinct, already established
        # module root retains this exact list across every loop continuation,
        # so releasing the generator frame cannot release the list itself.
        return any(refs == references and name not in state.deleted_globals
                   and self.engine.generator_stable_binding(name, self.engine.tree, original)
                   for name, refs in state.references.items() if not name.startswith('@'))

    def generator_value(self, target, node, inputs, bound, references, values, state, closure):
        """Create a supported frame without evaluating its yield."""
        if closure is not None:
            return None  # Live-cell lifetimes retain the existing refusal.
        captured_defaults = target if isinstance(target, _FunctionValue) else None
        function = captured_defaults.function if captured_defaults is not None else target
        signature = function.args
        positional = [arg.arg for arg in (*signature.posonlyargs, *signature.args)]
        parameters = (*positional, *(arg.arg for arg in signature.kwonlyargs))
        positions = self.call_positions(node, inputs.arguments, state)
        named = set(inputs.keywords)
        if (any(isinstance(expression, ast.Starred) for expression, *_rest in positions)
                or None in named or len(positions) > len(positional)
                or named - set(parameters) or named & set(positional[:len(signature.posonlyargs)])
                or named & set(positional[:len(positions)]) or set(parameters) - bound.keys()):
            raise AnalysisLimit('generator argument binding requires exact operands; analysis is incomplete')
        captured_values = {name: values.get(name) for name in parameters}
        for name, (expression, _fact, binding, _refs) in zip(positional, positions):
            if isinstance(expression, ast.Constant):
                captured_values[name] = expression
        for name, expression in inputs.keyword_nodes.items():
            if isinstance(expression, ast.Constant):
                captured_values[name] = expression
        for name, expression in zip(positional[-len(signature.defaults):], signature.defaults):
            if name not in positional[:len(positions)] and name not in named and isinstance(expression, ast.Constant):
                captured_values[name] = expression
        for argument, expression in zip(signature.kwonlyargs, signature.kw_defaults):
            if argument.arg not in named and isinstance(expression, ast.Constant):
                captured_values[argument.arg] = expression
        if self.generator_builtins_stable():
            for name, binding in captured_values.items():
                refs = references.get(name, NO_REFERENCES)
                if refs and all(isinstance(ref, ast.Call)
                                and self.expression_bindings.get(ref.func) in {'input', 'builtins.input'}
                                for ref in refs):
                    # Preserve the evaluated producer's lifetime evidence;
                    # the old input AST alone cannot recover that authority.
                    captured_values[name] = _GeneratorString(format_safe=bool(binding) and all(
                        isinstance(value, (_LiteralString, _GeneratorString)) and value.format_safe
                        for value in _binding_choices(binding)))
        retained = all(choices and all(isinstance(value, (_LiteralString, ast.Constant, _GeneratorString))
                                      for value in choices)
                       or self.generator_borrowed_capture(node, references.get(name, NO_REFERENCES), state)
                       for name, binding in captured_values.items() for choices in [_binding_choices(binding)])
        if not retained:
            raise AnalysisLimit('generator captured value lifetime is unresolved; analysis is incomplete')
        default_values = (dict(captured_defaults.values) if captured_defaults is not None
                          else self.definition_table('default_bindings', function))
        default_refs = (dict(captured_defaults.references) if captured_defaults is not None
                        else self.definition_table('default_references', function))
        default_syntax = dict(zip(positional[-len(signature.defaults):], signature.defaults))
        default_syntax.update((argument.arg, expression)
                              for argument, expression in zip(signature.kwonlyargs, signature.kw_defaults))
        # The frame also retains its function object. Even an overridden
        # default can therefore own a finalizer until that frame is released.
        for name, binding in default_values.items():
            choices = _binding_choices(binding)
            refs = default_refs.get(name, NO_REFERENCES)
            primitive_input = (self.generator_builtins_stable() and refs
                               and all(isinstance(ref, ast.Call)
                                       and self.expression_bindings.get(ref.func) in {'input', 'builtins.input'}
                                       for ref in refs))
            if not (isinstance(default_syntax.get(name), ast.Constant)
                    or choices and all(isinstance(value, (_LiteralString, ast.Constant, _GeneratorString))
                                    for value in choices) or primitive_input):
                raise AnalysisLimit('generator function default lifetime is unresolved; analysis is incomplete')
        self.possible_exception(state)
        ref = _CellRef(function, _GENERATOR_CURSOR, (node,))
        cells = state.cell_state()
        child = self.engine.original_calls.get(node, node)
        parent = self.engine.parents.get(child)
        while parent is not None and parent is not self.scope:
            if isinstance(parent, (ast.For, ast.AsyncFor, ast.While, ast.GeneratorExp,
                                   ast.ListComp, ast.SetComp, ast.DictComp)):
                if not isinstance(parent, (ast.For, ast.AsyncFor)) or child is not parent.iter:
                    cells.multiple.add(ref)
                    break
            child = parent
            parent = self.engine.parents.get(parent)
        if ref in cells.contents:
            cells.multiple.add(ref)
        state.put_cell(ref, _CellContents(binding=_GENERATOR_CREATED), written=True)
        return _DeferredGenerator(function, node,
                                  tuple((name, bound[name]) for name in parameters),
                                  tuple((name, references.get(name, NO_REFERENCES)) for name in parameters),
                                  tuple(captured_values.items()), ((_GENERATOR_CURSOR, ref),))

    def generator_step(self, node, state, generator):
        """Resume one read-only segment; return yield and exhaustion separately."""
        cursor = dict(generator.cells).get(_GENERATOR_CURSOR)
        if (state.cells is None or cursor not in state.cells.contents
                or cursor in state.cells.multiple):
            raise AnalysisLimit('generator cursor has ambiguous allocation; analysis is incomplete')
        contents = state.cells.contents[cursor]
        phases = _binding_choices(contents.binding)
        if (contents.bound is not True or not phases
                or not phases <= {_GENERATOR_CREATED, _GENERATOR_SUSPENDED, _GENERATOR_EXHAUSTED}):
            raise AnalysisLimit('generator cursor state is unresolved; analysis is incomplete')
        yielded, exhausted = [], []
        for phase in phases:
            branch = state.copy()
            if phase != _GENERATOR_CREATED:
                branch.put_cell(cursor, _CellContents(binding=_GENERATOR_EXHAUSTED), written=True)
                exhausted.append(branch)
                continue
            function = generator.function
            expression = function.body[-1].value.value
            binding, refs, fact = None, NO_REFERENCES, CLEAN
            if isinstance(expression, ast.Constant):
                binding = (_LiteralString(expression.value) if isinstance(expression.value, str) else expression)
            elif isinstance(expression, ast.Name):
                parameters = dict(generator.arguments)
                if expression.id in parameters:
                    fact = parameters[expression.id]
                    refs = dict(generator.references).get(expression.id, NO_REFERENCES)
                    binding = dict(generator.values).get(expression.id)
                else:
                    owner = self.engine.owner(function)
                    module_ref = owner.project.module_reference(owner) if owner.project is not None else None
                    if owner is not self.engine and module_ref is not None and module_ref in branch.mutated:
                        raise AnalysisLimit('generator defining module namespace was mutated; analysis is incomplete')
                    globals_ = {key: (value, objects, identity)
                                for key, value, objects, identity in self.global_arguments(function, branch)}
                    key = '@global:' + expression.id
                    missing = (owner is self.engine and isinstance(self.scope, ast.Module)
                               and expression.id not in branch.bindings and key not in branch.bindings)
                    if key in globals_ and not missing:
                        fact, refs, binding = globals_[key]
                        self.capture_globals.add((owner.tree, expression.id))
                    else:
                        binding = _implicit_identity(expression.id)
                        if binding is None:
                            branch.put_cell(cursor, _CellContents(binding=_GENERATOR_EXHAUSTED), written=True)
                            self.pending.append(_Completion('raise', branch, exception_type='NameError'))
                            continue
                        if not self.generator_builtins_stable(owner):
                            raise AnalysisLimit('generator implicit builtin binding is unresolved; analysis is incomplete')
                    # An abstract module binding can include a missing-name
                    # branch. Preserve that failure before yielding a value.
                    if None in _binding_choices(binding):
                        failed = branch.copy()
                        failed.put_cell(cursor, _CellContents(binding=_GENERATOR_EXHAUSTED), written=True)
                        self.pending.append(_Completion('raise', failed, exception_type='NameError'))
            fact = join_facts(fact, *(branch.heap.get(ref, CLEAN) for ref in refs))
            if refs & branch.mutated:
                binding = _without_object_contract(binding)
            branch.put_cell(cursor, _CellContents(binding=_GENERATOR_SUSPENDED), written=True)
            yielded.append((branch, fact, binding, refs))
        return yielded, _join_states(*exhausted)

    def next_generator(self, node, state, generator):
        yielded, exhausted = self.generator_step(node, state, generator)
        if exhausted is not None:
            self.pending.append(_Completion('raise', exhausted, exception_type='StopIteration'))
        state.replace(_join_states(*(branch for branch, _fact, _binding, _refs in yielded)))
        self.expression_bindings[node] = _join_bindings(*(binding for _branch, _fact, binding, _refs in yielded))
        self.expression_references[node] = frozenset().union(*(refs for _branch, _fact, _binding, refs in yielded))
        return join_facts(*(fact for _branch, fact, _binding, _refs in yielded))

    def generator_loop(self, node, state, generators):
        if (not isinstance(node, ast.For) or not isinstance(node.target, ast.Name)
                or not all(isinstance(value, _DeferredGenerator) for value in generators)):
            raise AnalysisLimit('generator iteration protocol is unmodeled; analysis is incomplete')
        finished, broken, outgoing = [], [], []
        for generator in generators:
            yielded, exhausted = self.generator_step(node, state, generator)
            finished.append(exhausted)
            for branch, fact, binding, refs in yielded:
                self.write_name(branch, node.target.id, _advance(fact, node.target.id), binding, refs)
                normal, pending = self.capture(node.body, branch)
                broken.extend(item.state for item in pending if item.kind == 'break')
                outgoing.extend(item for item in pending if item.kind not in {'break', 'continue'})
                for continuation in [normal, *(item.state for item in pending if item.kind == 'continue')]:
                    if continuation is None:
                        continue
                    more, exhausted = self.generator_step(node, continuation, generator)
                    if more:
                        raise AnalysisLimit('generator cursor restarted during iteration; analysis is incomplete')
                    finished.append(exhausted)
        self.pending.extend(_merge_completions(outgoing))
        normal = self.block(node.orelse, _join_states(*finished))
        return _join_states(normal, *broken)

    def map_cell_bindings(self, binding, map_ref, memo=None, *, map_objects=None):
        """Rewrite cell edges without traversing their possibly cyclic store."""
        # Evaluated defaults form a shared DAG. Visiting each immutable value
        # once keeps adding cell edges from expanding that DAG exponentially.
        memo = {} if memo is None else memo
        cached = memo.get(id(binding), _MISSING)
        if cached is not _MISSING:
            return cached
        choices = []
        for value in _binding_choices(binding):
            if isinstance(value, _ClosureValue):
                self.engine.budget.spend(1 + len(value.cells))
                value = _ClosureValue(self.map_cell_bindings(value.value, map_ref, memo, map_objects=map_objects),
                                      tuple((name, map_ref(ref)) for name, ref in value.cells))
            elif isinstance(value, _BoundClassMethod):
                value = _BoundClassMethod(self.map_cell_bindings(value.function, map_ref, memo,
                                                                map_objects=map_objects), value.owner,
                                          map_objects(value.references) if map_objects else value.references,
                                          value.receiver, value.valid)
            elif isinstance(value, _BoundCallable) and map_objects is not None:
                value = _BoundCallable(value.name, map_objects(value.references), value.receiver, value.namespace_proven)
            elif isinstance(value, _ArgumentVector) and map_objects is not None:
                value = _ArgumentVector(value.operands, tuple(map_objects(refs) for refs in value.references))
            elif isinstance(value, (_FunctionValue, _DeferredCall)):
                self.engine.budget.spend(1 + len(value.values))
                values = tuple((name, self.map_cell_bindings(child, map_ref, memo, map_objects=map_objects))
                               for name, child in value.values)
                references = (tuple((name, map_objects(refs)) for name, refs in value.references)
                              if map_objects is not None else value.references)
                value = (type(value)(value.function, value.call, value.arguments, references, values,
                                       tuple((name, map_ref(ref)) for name, ref in value.cells))
                         if isinstance(value, _DeferredCall) else
                         type(value)(value.function, value.arguments, references, values))
            choices.append(value)
        result = _join_bindings(*choices)
        memo[id(binding)] = result
        return result

    def prepare_cell_context(self, function, closure, values, state, candidate_keys, required):
        """Canonicalize the reachable lexical graph; bind its data separately."""
        owner = self.engine.owner(function)
        needed = owner.used_names[function] | {name for module, name in required if module is owner.tree}
        keys = set(candidate_keys) if candidate_keys is not None else set(values)
        keys.update(f'@global:{name}' for module, name in required if module is owner.tree)
        keys = sorted(key for key in keys if not key.startswith('@global:') or key[8:] in needed)
        actual, pending = {}, []

        def register(ref):
            slot = actual.get(ref)
            if slot is None:
                self.engine.budget.spend()
                slot = f'@cell:{len(actual)}'
                actual[ref] = slot
                pending.append(ref)
            return slot

        roots = tuple((name, register(ref)) for name, ref in closure.cells) if closure is not None else ()
        contextual = values.copy()
        for name in keys:
            contextual[name] = self.map_cell_bindings(values.get(name), register)
        entries, bound, references, bindings = [], {}, {}, {}
        index = 0
        while index < len(pending):
            ref = pending[index]
            index += 1
            slot = actual[ref]
            contents = self.cell_contents(ref, state)
            self.engine.budget.spend(1 + len(contents.fact) + len(contents.references)
                                     + sum(len(state.heap.get(obj, CLEAN)) for obj in contents.references))
            binding = (_without_object_contract(contents.binding)
                       if contents.references & state.mutated else contents.binding)
            entries.append((slot, self.map_cell_bindings(binding, register), contents.bound,
                            state.cells is not None and ref in state.cells.multiple))
            bound[slot] = join_facts(contents.fact, *(state.heap.get(obj, CLEAN) for obj in contents.references))
            references[slot] = contents.references
            bindings[slot] = binding
        if entries:
            contextual['@cells'] = _CellGraph(roots, tuple(entries))
            keys.append('@cells')
        return contextual, keys, {slot: ref for ref, slot in actual.items()}, bound, references, bindings

    def export_cells(self, state, bindings=()):
        if state is None or state.cells is None:
            return ()
        pending = list(state.cells.written)
        seen = set()

        def retain(ref):
            pending.append(ref)
            return ref

        for binding in bindings:
            self.map_cell_bindings(binding, retain)
        result = []
        while pending:
            ref = pending.pop()
            if ref in seen:
                continue
            seen.add(ref)
            contents = self.cell_contents(ref, state)
            self.engine.budget.spend(1 + len(contents.fact) + len(contents.references)
                                     + sum(len(state.heap.get(obj, CLEAN)) for obj in contents.references))
            binding = self.refresh_function_defaults(contents.binding, state.heap, state.mutated)
            if contents.references & state.mutated:
                binding = _without_object_contract(binding)
            self.map_cell_bindings(binding, retain)
            result.append((ref, _CellContents(
                join_facts(contents.fact, *(state.heap.get(obj, CLEAN) for obj in contents.references)),
                contents.references, binding, contents.bound)))
        return tuple(result)

    def apply_cells(self, items, multiple, cell_map, state, node, bound, references, values, substitute):
        """Instantiate local cells once and project incoming-cell replacements."""
        if not items:
            return
        cells = state.cell_state()

        def mapped(ref):
            if ref in cell_map:
                return cell_map[ref]
            if isinstance(ref, str):
                raise AnalysisLimit('unbound symbolic lexical cell; analysis is incomplete')
            # Concrete refs are allocations owned by the summarized frame.
            # Recursion can give the caller an equal local allocation site;
            # it still denotes a different invocation. Incoming live cells
            # have canonical slots and were mapped above before this branch.
            sites = (node, *ref.sites)
            target = _CellRef(ref.owner, ref.name, sites[-2:])
            cell_map[ref] = target
            repeated = len(sites) > 2 or ref in multiple
            child, parent = node, self.engine.parents.get(node)
            while parent is not None and parent is not self.scope:
                if isinstance(parent, (ast.For, ast.AsyncFor, ast.While, ast.GeneratorExp,
                                       ast.ListComp, ast.SetComp, ast.DictComp)):
                    if (ref.name != _GENERATOR_CURSOR
                            or not isinstance(parent, (ast.For, ast.AsyncFor)) or child is not parent.iter):
                        repeated = True
                        break
                child = parent
                parent = self.engine.parents.get(parent)
            if repeated:
                cells.multiple.add(target)
            return target

        for ref, _contents in items:
            mapped(ref)
        for ref, contents in items:
            target = mapped(ref)
            actual_refs = frozenset().union(*(
                self._lookup_refs(references, obj) if isinstance(obj, str) else frozenset({node})
                for obj in contents.references))
            binding = self.substitute_binding(contents.binding, bound, references, node, '<closure>()',
                                              values, substitute=substitute, cells=cell_map)
            projected = _CellContents(substitute(contents.fact), actual_refs, binding, contents.bound)
            self.engine.budget.spend(1 + len(cells.names) + len(actual_refs))
            state.put_cell(target, projected, written=True, weak=target in cells.multiple)

    def export_globals(self, state):
        if state is None or not state.global_writes:
            return ()
        result = []
        for name, write in sorted(state.global_writes.items()):
            contents = write.current
            self.engine.budget.spend(1 + len(contents.fact) + len(contents.references)
                                     + sum(len(state.heap.get(ref, CLEAN)) for ref in contents.references))
            binding = self.refresh_function_defaults(contents.binding, state.heap, state.mutated)
            if contents.references & state.mutated:
                binding = _without_object_contract(binding)
            result.append((self.engine.tree, name, _CellContents(
                join_facts(contents.fact, *(state.heap.get(ref, CLEAN) for ref in contents.references)),
                contents.references, binding, contents.bound)))
        return tuple(result)

    def apply_globals(self, items, cell_map, state, node, bound, references, values, substitute, *, weak=False):
        for module, name, contents in items:
            if module is not self.engine.tree:
                raise AnalysisLimit('foreign module global write; analysis is incomplete')
            if name in state.deleted_globals and '@global:' + name in contents.references:
                # A conditional setter can carry its unchanged input through
                # the summary. That is not a definite recreation after del.
                raise AnalysisLimit('conditional global creation or deletion; analysis is incomplete')
            actual_refs = frozenset().union(*(
                self._lookup_refs(references, ref) if isinstance(ref, str) else frozenset({node})
                for ref in contents.references))
            binding = self.substitute_binding(contents.binding, bound, references, node, '<global>()',
                                              values, substitute=substitute, cells=cell_map)
            projected = _CellContents(substitute(contents.fact), actual_refs, binding, contents.bound)
            if weak:
                projected = _join_cells(self.global_contents(name, state), projected)
            self.put_global(name, projected, state)

    def assign(self, target, fact, state, value=None, *, target_references=None, deleting=False):
        if (not isinstance(target, ast.Name)
                and any(isinstance(choice, (_DeferredGenerator, _GeneratorNext))
                        for choice in _binding_choices(self.expression_bindings.get(value)))):
            raise AnalysisLimit('generator stored or unpacked outside a name; analysis is incomplete')
        if isinstance(target, ast.Name):
            self.write_name(state, target.id, _advance(fact, target.id), self.expression_bindings.get(value),
                            self.expression_references.get(value, NO_REFERENCES))
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
            self.escape_literal_mapping(self.expression_bindings.get(value),
                                        self.expression_references.get(value, NO_REFERENCES), state)
            if any(isinstance(choice, _PartialValue)
                   for choice in _binding_choices(self.expression_bindings.get(value))):
                raise AnalysisLimit('functools.partial stored in an object; analysis is incomplete')
            if any(isinstance(choice, _GlobalNamespace)
                   for choice in _binding_choices(self.expression_bindings.get(value))):
                raise AnalysisLimit('globals mapping stored in an object; analysis is incomplete')
            # Heap value facts do not preserve a stored callable's identity.
            # Retain its namespace-producing authority for the final summary
            # check instead of silently forgetting a globals() factory.
            for choice in _binding_choices(self.expression_bindings.get(value)):
                if isinstance(choice, str):
                    if choice in ('globals', 'builtins.globals'):
                        self.engine.escaping_callables[choice] = None
                elif isinstance(choice, (_FunctionValue, _ClosureValue, _DeferredCall, _BoundCallable,
                                         _BoundClassMethod, ast.FunctionDef,
                                         ast.AsyncFunctionDef, ast.Lambda)):
                    self.engine.escaping_callables[choice] = None
            if target_references is None:
                self.expr(target.value, state)
                target_references = self.expression_references.get(target.value, NO_REFERENCES)
                # The receiver precedes an index that can rebind its name.
                if isinstance(target, ast.Subscript):
                    self.expr(target.slice, state)
            namespace = self.expression_bindings.get(target.value)
            for choice in _binding_choices(namespace):
                function = choice.function if isinstance(choice, (_FunctionValue, _ClosureValue)) else choice
                if isinstance(choice, (_DeferredGenerator, _GeneratorNext)):
                    raise AnalysisLimit('generator object mutation is unmodeled; analysis is incomplete')
                if isinstance(function, ast.FunctionDef) and function in self.engine.generators:
                    raise AnalysisLimit('generator function metadata mutation is unmodeled; analysis is incomplete')
            if (not isinstance(namespace, _GlobalNamespace)
                    and any(isinstance(choice, _GlobalNamespace) for choice in _binding_choices(namespace))):
                raise AnalysisLimit('ambiguous globals mapping write; analysis is incomplete')
            if isinstance(namespace, _GlobalNamespace):
                if not isinstance(target, ast.Subscript) or namespace.member is not None:
                    raise AnalysisLimit('unsupported globals mapping member write; analysis is incomplete')
                if deleting:
                    raise AnalysisLimit('global deletion requires namespace lifetime analysis; analysis is incomplete')
                self.write_global(namespace, target.slice, fact, value, state)
                return
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
                    self.write_name(state, base.id, join_facts(state.get(base.id, CLEAN), _advance(fact, base.id)),
                                    state.bindings.get(base.id))

    def namespace_keys(self, namespace, key):
        if namespace.module is not self.engine.tree:
            raise AnalysisLimit('foreign globals mapping access; analysis is incomplete')
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return (key.value,)
        choices = _binding_choices(self.expression_bindings.get(key))
        self.engine.budget.spend(len(choices))
        # A finite join of literal strings is a closed set of builtin keys.
        # Unknown alternatives must stay refused: they can name other globals
        # and may execute user-defined hash/equality callbacks during lookup.
        if not choices or any(not isinstance(choice, _LiteralString) for choice in choices):
            raise AnalysisLimit('dynamic globals mapping key; analysis is incomplete')
        names = tuple(sorted({choice.value for choice in choices}))
        if (len(names) > 1 and self.class_environments
                and (not self.generator_builtins_stable() or any(
                    scope.bases or scope.keywords or scope.decorator_list
                    for scope, _outer in self.class_environments))):
            # LOAD_NAME can consult a metaclass's custom __prepare__ mapping.
            # Lexical outer bindings cannot certify its globals factory/key.
            raise AnalysisLimit('finite globals access in an unresolved class namespace; analysis is incomplete')
        return names

    def write_global(self, namespace, key, fact, value, state):
        names = self.namespace_keys(namespace, key)
        if any(name not in self.engine.global_names for name in names):
            raise AnalysisLimit('new globals mapping declaration; analysis is incomplete')
        for name in names:
            contents = _CellContents(_advance(fact, name),
                                    self.expression_references.get(value, NO_REFERENCES),
                                    self.expression_bindings.get(value))
            if len(names) > 1:
                # One runtime key is written. Every other candidate retains
                # its incoming facts, aliases and callable/sanitizer identity.
                previous = self.global_contents(name, state)
                if previous.bound is True and not self.namespace_replacement_inert(previous.binding):
                    # Replacing the last owning reference can execute a
                    # finalizer, including one retained by a function's
                    # defaults, annotations, attributes or closure cells.
                    raise AnalysisLimit('finite globals replacement lifetime is unresolved; analysis is incomplete')
                contents = _join_cells(previous, contents)
            self.put_global(name, contents, state)
            self.engine.rebound_globals.add(name)

    def namespace_replacement_inert(self, binding):
        native = {'eval', 'exec', 'input', 'print', 'str', 'any', 'all', 'next',
                  'globals', 'staticmethod', 'classmethod'}
        for choice in _binding_choices(binding):
            self.engine.budget.spend()
            if isinstance(choice, _LiteralString) or isinstance(choice, ast.Constant):
                continue
            if (isinstance(choice, str) and choice.removeprefix('builtins.') in native
                    and self.generator_builtins_stable()):
                continue
            return False
        return True

    def read_global(self, namespace, key, state):
        names = self.namespace_keys(namespace, key)
        facts, bindings, references, present = [], [], [], True
        for name in names:
            if name in self.engine.global_names:
                self.capture_globals.add((self.engine.tree, name))
                self.engine.namespace_read_names.add(name)
            values, source = self.global_namespace(name, state)
            presence = _namespace_presence(state if '@presence:' + name in state.bindings else values, name)
            refs = values.references.get(source, NO_REFERENCES)
            facts.append(join_facts(values.value(source), *(state.heap.get(ref, CLEAN) for ref in refs)))
            bindings.append(values.bindings.get(source))
            references.append(refs)
            present &= presence == _NAMESPACE_PRESENT
        return join_facts(*facts), _join_bindings(*bindings), frozenset().union(*references), present

    def condition(self, node, state, *, inert=False):
        """Return truthy/falsy successors, preserving ordered guard effects."""
        if state is None or not state.reachable:
            return None, None
        if isinstance(node, ast.BoolOp):
            stopped = []
            continuation = state
            for operand in node.values:
                truthy, falsy = self.condition(operand, continuation, inert=inert)
                if isinstance(node.op, ast.And):
                    continuation = truthy
                    stopped.append(falsy)
                else:
                    continuation = falsy
                    stopped.append(truthy)
            return ((continuation, _join_states(*stopped)) if isinstance(node.op, ast.And)
                    else (_join_states(*stopped), continuation))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            truthy, falsy = self.condition(node.operand, state, inert=inert)
            return falsy, truthy
        if isinstance(node, ast.IfExp):
            left, right = self.condition(node.test, state, inert=inert)
            left_true, left_false = self.condition(node.body, left, inert=inert)
            right_true, right_false = self.condition(node.orelse, right, inert=inert)
            return _join_states(left_true, right_true), _join_states(left_false, right_false)
        self.expr(node, state)
        return self.evaluated_truth(node, state, inert=inert)

    def evaluated_truth(self, node, state, *, inert=False):
        """Split an evaluated operand without executing its effects twice."""
        if not state.reachable:
            return None, None
        if inert and not self.materialized_generator_inert(node, state):
            raise AnalysisLimit('generator predicate truth protocol is unresolved; analysis is incomplete')
        literal = node.value if isinstance(node, ast.NamedExpr) else node
        if isinstance(literal, ast.Constant):
            return (state, None) if bool(literal.value) else (None, state)
        binding = self.expression_bindings.get(node)
        if isinstance(binding, _LiteralString):
            return (state, None) if binding.value else (None, state)
        if (isinstance(binding, ast.Constant)
                and type(binding.value) in {str, bytes, int, float, complex, bool, type(None)}):
            return (state, None) if bool(binding.value) else (None, state)
        if (inert and isinstance(binding, _ArgumentVector)
                and all(not isinstance(value, _ArgumentExpansion) for value, _fact in binding.operands)):
            # Tuple/list truth depends on their captured length, not their
            # elements' truth. The inert proof above also covers teardown.
            return (state, None) if binding.operands else (None, state)
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
            self.write_name(state, name, _advance(fact, name), binding, references)

    def source(self, node, state, candidate=None):
        # A supplied candidate was resolved before a call's argument effects.
        if candidate is not None:
            pass
        elif isinstance(node, ast.Call):
            func_q = _qualified(node.func, state.bindings)
            if not func_q:
                return CLEAN
            candidate = func_q + '('
        elif isinstance(node, ast.Subscript):
            base = _qualified(node.value, state.bindings)
            if base == 'params':
                candidate = 'params[...]'
            elif base == 'event' and isinstance(node.slice, ast.Constant) and node.slice.value == 'body':
                candidate = "event['body']"
            else:
                return CLEAN
        elif isinstance(node, (ast.Name, ast.Attribute)):
            candidate = _qualified(node, state.bindings)
        else:
            return CLEAN
        if not candidate or candidate == '(':
            return CLEAN
        if candidate.startswith('@request:'):
            qualified = candidate.removeprefix('@request:').removesuffix('(')
            request_type, _, member = qualified.rpartition('.')
            if request_type in _REQUEST_TYPES and member in _REQUEST_MEMBERS:
                return frozenset({TaintTrace(qualified, path=(qualified,))})
            return CLEAN
        if not _SOURCE_FAST_RE.search(candidate):
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
        if not isinstance(self.scope, ast.Module):
            # Escaped raw callables still read their cells from the caller's
            # namespace. Previously every scope eagerly included every name
            # captured anywhere in the module, making unrelated closures
            # retain quadratic state. Supply an omitted global only when an
            # actual callee needs it, with the same symbolic identity and live
            # heap as that earlier initialization. Names belonging to this
            # scope (including deleted names) must keep their current state.
            used = self.engine.used_names.get(self.scope, ())
            for name in self.engine.closures.get(function, ()):
                if (name not in self.engine.closure_names or name in used
                        or name in namespace or name in namespace.bindings
                        or name in namespace.references):
                    continue
                symbolic = self.engine.global_symbols.get(name)
                binding = self.engine.globals.bindings.get(name, _MISSING)
                if symbolic is None and binding is _MISSING:
                    continue
                if namespace is state:
                    namespace = state.copy()
                if symbolic is not None:
                    namespace[name] = symbolic[0]
                    namespace.references[name] = symbolic[1]
                if binding is not _MISSING:
                    namespace.bindings[name] = binding
        return namespace

    def definition_table(self, table, function):
        """A callee's definition-time defaults, recorded as a job input."""
        value = getattr(self.engine, table).get(function)
        if self.engine.reads is not None:
            self.engine.reads[(table, function)] = value
        return value if value is not None else {}

    def function_value(self, function, state):
        defaults = self.engine.defaults.get(function, {})
        value = function
        if defaults and not isinstance(self.engine.parents.get(function), (ast.Module, ast.ClassDef)):
            self.engine.budget.spend(len(defaults))
            value = _FunctionValue(function, tuple(defaults.items()),
                                   tuple(self.engine.default_references.get(function, {}).items()),
                                   tuple(self.engine.default_bindings.get(function, {}).items()))
        names = self.engine.closures.get(function, ())
        if names:
            value = _ClosureValue(value, tuple((name, self.lexical_cell(function, name, state))
                                               for name in sorted(names)))
        return value

    def refresh_function_defaults(self, binding, heap, mutated):
        """Escaping defaults/vectors retain writes to their captured objects."""
        if not isinstance(binding, (_FunctionValue, _ClosureValue, _ArgumentVector, frozenset)):
            return binding
        choices = []
        for value in _binding_choices(binding):
            if isinstance(value, _ClosureValue):
                value = _ClosureValue(self.refresh_function_defaults(value.value, heap, mutated), value.cells)
            elif isinstance(value, _ArgumentVector):
                self.engine.budget.spend(1 + len(value.operands)
                                         + sum(len(refs) for refs in value.references))
                operands = []
                for index, (operand, fact) in enumerate(value.operands):
                    refs = value.references_at(index)
                    self.engine.budget.spend(len(fact) + sum(len(heap.get(ref, CLEAN)) for ref in refs))
                    operands.append((operand, join_facts(fact, *(heap.get(ref, CLEAN) for ref in refs))))
                value = _ArgumentVector(tuple(operands), value.references)
            elif isinstance(value, _FunctionValue):
                self.engine.budget.spend(1 + len(value.arguments))
                references = dict(value.references)
                arguments = []
                for name, fact in value.arguments:
                    refs = references.get(name, NO_REFERENCES)
                    self.engine.budget.spend(len(fact) + len(refs)
                                             + sum(len(heap.get(ref, CLEAN)) for ref in refs))
                    arguments.append((name, join_facts(fact, *(heap.get(ref, CLEAN) for ref in refs))))
                values = []
                for name, captured in value.values:
                    if references.get(name, NO_REFERENCES) & mutated:
                        captured = _without_object_contract(captured)
                    values.append((name, self.refresh_function_defaults(captured, heap, mutated)))
                value = type(value)(value.function, tuple(arguments), value.references, tuple(values))
            choices.append(value)
        return _join_bindings(*choices)

    def global_arguments(self, function, state):
        """A helper reads its defining module, never a caller's same-name local."""
        owner = self.engine.owner(function)
        if not owner.global_names:
            return
        module_ref = (owner.project.module_reference(owner) if owner.project is not None else None)
        same_engine = owner is self.engine
        is_fn_scope = same_engine and not isinstance(self.scope, ast.Module)
        comp_envs = self.comprehension_environments if same_engine else ()
        shadowed_in_scope = (
            (self.engine.locals.get(self.scope, set()) | self.engine.closures.get(self.scope, set()))
            if is_fn_scope
            else ()
        )
        caller_used = self.engine.used_names.get(self.scope) if is_fn_scope else None
        state_heap = state.heap
        state_mutated = state.mutated
        state_bindings = state.bindings
        owner_bindings = owner.globals.bindings
        module_heap_fact = state_heap.get(module_ref, CLEAN) if module_ref is not None and state_heap else CLEAN
        module_mutated = module_ref in state_mutated if module_ref is not None and state_mutated else False
        default_namespace = (self.class_environments[0][1] if same_engine and self.class_environments
                             else state if same_engine else owner.globals)
        for name in owner.global_names:
            key = f'@global:{name}'
            presence_key = '@presence:' + name
            if same_engine and key in state.bindings:
                yield key, state.value(key), state.references.get(key, NO_REFERENCES), state.bindings[key]
                yield presence_key, CLEAN, NO_REFERENCES, _namespace_presence(state, name)
                continue
            if shadowed_in_scope and name in shadowed_in_scope:
                fact, refs, value = owner.global_symbols[name]
                yield key, fact, refs, value
                yield presence_key, CLEAN, NO_REFERENCES, _namespace_presence(
                    state if presence_key in state.bindings else owner.globals, name)
                continue
            if caller_used is not None and name not in caller_used and name not in state_bindings:
                sym_fact, refs, _ = owner.global_symbols[name]
                fact = join_facts(sym_fact, state_heap[key]) if (state_heap and key in state_heap) else sym_fact
                if module_heap_fact:
                    fact = join_facts(fact, module_heap_fact)
                value = owner_bindings.get(name)
                if value is not None and state_mutated and (module_mutated or key in state_mutated):
                    value = _without_object_contract(value)
                yield key, fact, refs, value
                yield presence_key, CLEAN, NO_REFERENCES, _namespace_presence(
                    state if presence_key in state.bindings else owner.globals, name)
                continue
            namespace = default_namespace
            if comp_envs and not self.class_environments:
                for comprehension, outer in comp_envs:
                    if name in self.engine.locals[comprehension]:
                        namespace = outer
                        break
            refs = namespace.references.get(name, NO_REFERENCES)
            base_fact = namespace.value(name)
            if state_heap and (module_heap_fact or (refs and namespace is not state)):
                fact = join_facts(base_fact, module_heap_fact, *(state_heap.get(ref, CLEAN) for ref in refs))
            elif module_heap_fact:
                fact = join_facts(base_fact, module_heap_fact)
            else:
                fact = base_fact
            value = namespace.bindings.get(name)
            if state_mutated and (module_mutated or (refs and (refs & state_mutated))):
                value = _without_object_contract(value)
            yield key, fact, refs, value
            yield presence_key, CLEAN, NO_REFERENCES, _namespace_presence(
                state if same_engine and presence_key in state.bindings else namespace, name)

    def call_positions(self, node, arguments=None, state=None):
        """Expand evaluated, exact *vectors without re-evaluating their AST.

        Keep unknown expansions in place so all binders agree on when an
        argument can shift. References remain conservative for saved elements.
        """
        if arguments is None:
            arguments = [self.expression_facts.get(arg, CLEAN) for arg in node.args]
        positions = []
        for expression, fact in zip(node.args, arguments):
            binding = self.expression_bindings.get(expression)
            refs = self.expression_references.get(expression, NO_REFERENCES)
            if isinstance(expression, ast.Starred):
                self.require_value(binding)
            if (isinstance(expression, ast.Starred) and isinstance(binding, _ArgumentVector)
                    and not any(isinstance(operand, _ArgumentExpansion) for operand, _ in binding.operands)):
                self.engine.budget.spend(len(binding.operands))
                for index, (operand, value) in enumerate(binding.operands):
                    identity = (operand if isinstance(operand, (_LiteralString, _SymbolicValue, frozenset))
                                else self.expression_bindings.get(operand))
                    element_refs = (NO_REFERENCES if isinstance(operand, _LiteralString)
                                    else binding.references_at(index) if binding.references
                                    else self.expression_references.get(operand, refs))
                    if state is not None:
                        self.engine.budget.spend(len(element_refs)
                                                 + sum(len(state.heap.get(ref, CLEAN)) for ref in element_refs))
                        value = join_facts(value, *(state.heap.get(ref, CLEAN) for ref in element_refs))
                        if element_refs & state.mutated:
                            identity = _without_object_contract(identity)
                    positions.append((operand, value, identity, element_refs))
            else:
                positions.append((expression, fact, binding, refs))
        return positions

    def bind(self, function, node, arguments, keywords, state, globals_snapshot=None, captured_defaults=None,
             closure=None):
        positions = self.call_positions(node, arguments, state)
        arguments = [fact for _expression, fact, _binding, _refs in positions]
        positional = [arg.arg for arg in (*function.args.posonlyargs, *function.args.args)]
        bound = {name: fact for name, fact in zip(positional, arguments)}
        for name, fact in keywords.items():
            if name is not None:
                bound[name] = fact
        defaults = dict(zip(positional[-len(function.args.defaults):], function.args.defaults)) if function.args.defaults else {}
        defaults.update((arg.arg, default) for arg, default in zip(function.args.kwonlyargs, function.args.kw_defaults)
                        if default is not None)
        if defaults:
            default_facts = (dict(captured_defaults.arguments) if captured_defaults is not None
                             else self.definition_table('defaults', function))
            default_references = (dict(captured_defaults.references) if captured_defaults is not None
                                  else self.definition_table('default_references', function))
        for name, default in defaults.items():
            if name not in bound:
                references = default_references.get(name, NO_REFERENCES)
                bound[name] = join_facts(default_facts.get(name, CLEAN),
                                         *(state.heap.get(ref, CLEAN) for ref in references))
        expanded = join_facts(*(fact for arg, fact, _binding, _refs in positions if isinstance(arg, ast.Starred)),
                              keywords.get(None, CLEAN))
        if expanded:
            for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
                bound[arg.arg] = join_facts(bound.get(arg.arg, CLEAN), expanded)
        if function.args.vararg:
            bound[function.args.vararg.arg] = join_facts(*arguments[len(positional):], expanded)
        if function.args.kwarg:
            accepted = set(positional) | {arg.arg for arg in function.args.kwonlyargs}
            bound[function.args.kwarg.arg] = join_facts(*(fact for name, fact in keywords.items() if name not in accepted))
        captured = self.closure_environment(function, state, closure)
        for name in self.engine.closures.get(function, ()):
            bound[f'@free:{name}'] = captured.value(name)
        global_items = globals_snapshot if globals_snapshot is not None else self.global_arguments(function, state)
        for key, fact, _refs, _value in global_items:
            bound[key] = fact
        return bound

    def bind_references(self, function, node, keyword_nodes, state, globals_snapshot=None, captured_defaults=None,
                        closure=None):
        """Bind references from evaluated argument snapshots, never re-read names.

        Variadic packs are new Python containers, not aliases to their values.
        Ordinary positional/keyword parameters and literal ** maps retain
        object identity. Unknown expansion is conservatively a may-alias set.
        """
        positional = [arg.arg for arg in (*function.args.posonlyargs, *function.args.args)]
        accepted = set(positional) | {arg.arg for arg in function.args.kwonlyargs}
        positions = self.call_positions(node, state=state)
        bound = {name: item[3] for name, item in zip(positional, positions)}
        for name, expression in keyword_nodes.items():
            if name in accepted:
                bound[name] = self.expression_references.get(expression, NO_REFERENCES)
        defaults = (captured_defaults.references if captured_defaults is not None
                    else self.definition_table('default_references', function).items())
        for name, references in defaults:
            bound.setdefault(name, references)
        expanded = frozenset().union(*(refs for arg, _fact, _binding, refs in positions
                                      if isinstance(arg, ast.Starred)))
        if expanded:
            for name in positional:
                bound[name] = bound.get(name, NO_REFERENCES) | expanded
        captured = self.closure_environment(function, state, closure)
        for name in self.engine.closures.get(function, ()):
            bound[f'@free:{name}'] = captured.references.get(name, NO_REFERENCES)
        global_items = globals_snapshot if globals_snapshot is not None else self.global_arguments(function, state)
        for key, _fact, refs, _value in global_items:
            bound[key] = refs
        return bound

    def _lookup_refs(self, references, key):
        if key == _PARTIAL_MODULE_REF:
            return frozenset({key})
        res = references.get(key)
        if res is not None:
            return res
        if self.engine.project is not None:
            return self.engine.project.module_ref_map.get(key, NO_REFERENCES)
        return NO_REFERENCES

    def bind_values(self, function, node, arguments, keyword_nodes, state, globals_snapshot=None, captured_defaults=None,
                    closure=None):
        positional = [arg.arg for arg in (*function.args.posonlyargs, *function.args.args)]
        positions = self.call_positions(node, arguments, state)
        bound = {name: item[2] for name, item in zip(positional, positions)}
        expanded = any(isinstance(item[0], ast.Starred) for item in positions)
        if expanded:
            # Unknown expansion must not certify a particular program/option.
            bound.update((name, None) for name in positional)
        if function.args.vararg:
            operands = []
            element_references = []
            for expression, fact, binding, refs in positions[len(positional):]:
                if isinstance(expression, ast.Starred) and isinstance(binding, _ArgumentVector):
                    operands.extend(binding.operands)
                    element_references.extend(binding.references if binding.references else
                                              (refs for _ in binding.operands))
                else:
                    operands.append(self.command_operand(expression, fact))
                    element_references.append(refs)
            bound[function.args.vararg.arg] = (
                None if expanded and positional else _ArgumentVector(tuple(operands), tuple(element_references)))
        bound.update((name, self.expression_bindings.get(value)) for name, value in keyword_nodes.items()
                     if name is not None)
        defaults = (captured_defaults.values if captured_defaults is not None
                    else self.definition_table('default_bindings', function).items())
        for name, value in defaults:
            bound.setdefault(name, value)
        captured = self.closure_environment(function, state, closure)
        for name in self.engine.closures.get(function, ()):
            bound[f'@free:{name}'] = captured.bindings.get(name)
        global_items = globals_snapshot if globals_snapshot is not None else self.global_arguments(function, state)
        for key, _fact, _refs, value in global_items:
            bound[key] = value
        return bound

    def bind_vector_elements(self, bound, references, values, state, candidate_keys=None):
        """Bind summary projections to this invocation's positional facts.

        Separate slots for each shape retain branch correlation (echo data
        must not become a different branch's Python source). Facts and their
        provenance live here, never in summary context keys.
        """
        projected = {}
        items = (((name, values.get(name)) for name in candidate_keys)
                 if candidate_keys is not None else values.items())
        for name, binding in items:
            for vector in _binding_choices(binding):
                if isinstance(vector, _ArgumentVector):
                    self.engine.budget.spend(sum(len(refs) for refs in vector.references))
            for variant, shape, vectors in _vector_variants(binding):
                self.engine.budget.spend(len(shape) * len(vectors))
                aggregate = []
                for index in range(len(shape)):
                    slot = _vector_slot(name, variant, index)
                    refs = frozenset().union(*(vector.references_at(index) for vector in vectors))
                    self.engine.budget.spend(len(refs) + sum(len(state.heap.get(ref, CLEAN)) for ref in refs))
                    references[slot] = refs
                    bound[slot] = join_facts(*(vector.operands[index][1] for vector in vectors),
                                            *(state.heap.get(ref, CLEAN) for ref in refs))
                    aggregate.append(bound[slot])
                    projected[slot] = _join_bindings(*(
                        operand if isinstance(operand, (_LiteralString, _SymbolicValue, frozenset)) else None
                        for operand, _fact in (vector.operands[index] for vector in vectors)))
                # Unknown indices/slices and widened suffixes still use the
                # aggregate parameter. Its provenance must include these same
                # live element writes even when no exact projection is possible.
                bound[name] = join_facts(bound.get(name, CLEAN), *aggregate)
        values.update(projected)

    @staticmethod
    def bind_method_receivers(bound, references, values, state, candidate_keys=None):
        """Bind callback receivers separately from the callable object itself.

        A helper taking a bound method may mutate its class even though it
        never receives that class as a positional argument. Symbolic receiver
        slots carry those effects through the ordinary summary substitution.
        Concrete heaps and evidence never become callable context keys.
        """
        items = ((name, values.get(name)) for name in candidate_keys) if candidate_keys is not None else tuple(values.items())
        for name, binding in items:
            if not isinstance(binding, (_BoundCallable, _BoundClassMethod)) and not (
                isinstance(binding, frozenset) and any(isinstance(v, (_BoundCallable, _BoundClassMethod)) for v in binding)
            ):
                continue
            choices = []
            receivers, refs = [], []
            for value in _binding_choices(binding):
                if isinstance(value, (_BoundCallable, _BoundClassMethod)):
                    receivers.append(join_facts(value.receiver, *(state.heap.get(ref, CLEAN)
                                                                  for ref in value.references)))
                    refs.append(value.references)
                    if isinstance(value, _BoundClassMethod):
                        value = _BoundClassMethod(value.function, value.owner, value.references, value.receiver,
                                                  value.valid and not bool(value.references & state.mutated))
                    elif value.name == _LITERAL_MAPPING_GET and value.references & state.mutated:
                        value = _BoundCallable('<object>.get', value.references, value.receiver)
                choices.append(value)
            if refs:
                slot = '@method:' + name
                bound[slot] = join_facts(*receivers)
                references[slot] = frozenset().union(*refs)
                values[name] = _join_bindings(*choices)

    def bind_function_defaults(self, bound, references, values, state, candidate_keys=None,
                               *, function=None, summary=None):
        """Project captured defaults through symbolic callback slots.

        A callback summary can be shared by safe and unsafe factory results:
        their body identity is the same, but their default values are not.
        """
        owner = self.engine.owner(function) if function is not None else self.engine
        required = summary.capture_globals if summary is not None else frozenset()
        if summary is not None and summary.incomplete:
            candidate_keys = None
        if candidate_keys is not None:
            candidate_keys = dict.fromkeys(candidate_keys)
            candidate_keys.update((f'@global:{name}', None) for module, name in required
                                  if module is owner.tree)
        direct_globals = (owner.used_names[function]
                          if summary is not None and not summary.incomplete else None)
        items = (((name, values.get(name)) for name in candidate_keys)
                 if candidate_keys is not None else values.items())
        pending = []
        captured_keys = set()
        for name, binding in items:
            if (direct_globals is not None and name.startswith('@global:')
                    and name[8:] not in direct_globals
                    and (owner.tree, name[8:]) not in required):
                continue
            if not any(isinstance(value, (_FunctionValue, _ClosureValue, _BoundCallable, _BoundClassMethod))
                       for value in _binding_choices(binding)):
                continue
            if (name.startswith('@global:') and summary is not None and not summary.incomplete
                    and (owner.tree, name[8:]) not in required
                    and name[8:] not in self.context_globals
                    and _same_witness(binding, owner.globals.bindings.get(name[8:]))):
                continue
            pending.append((name, binding))
        self.engine.budget.spend(len(pending))
        while pending:
            name, binding = pending.pop()
            for value in _binding_choices(binding):
                if isinstance(value, _ClosureValue):
                    value = value.value
                if isinstance(value, (_BoundCallable, _BoundClassMethod)):
                    slot = '@method:' + name
                    refs = value.references
                    self.engine.budget.spend(1 + len(value.receiver) + len(refs)
                                             + len(bound.get(slot, CLEAN))
                                             + len(references.get(slot, NO_REFERENCES))
                                             + sum(len(state.heap.get(ref, CLEAN)) for ref in refs))
                    bound[slot] = join_facts(bound.get(slot, CLEAN), value.receiver,
                                            *(state.heap.get(ref, CLEAN) for ref in refs))
                    references[slot] = references.get(slot, NO_REFERENCES) | refs
                    continue
                if not isinstance(value, _FunctionValue):
                    continue
                self.engine.budget.spend(1 + len(value.arguments))
                default_refs = dict(value.references)
                default_values = dict(value.values)
                for parameter, fact in value.arguments:
                    slot = f'@default:{name}:{parameter}'
                    refs = default_refs.get(parameter, NO_REFERENCES)
                    self.engine.budget.spend(len(fact) + len(refs)
                                             + len(bound.get(slot, CLEAN))
                                             + len(references.get(slot, NO_REFERENCES))
                                             + sum(len(state.heap.get(ref, CLEAN)) for ref in refs))
                    bound[slot] = join_facts(bound.get(slot, CLEAN), fact,
                                            *(state.heap.get(ref, CLEAN) for ref in refs))
                    references[slot] = references.get(slot, NO_REFERENCES) | refs
                    captured = default_values.get(parameter)
                    self.engine.budget.spend(len(_binding_choices(captured))
                                             + (len(_binding_choices(values[slot])) if slot in values else 0))
                    values[slot] = (_join_bindings(values[slot], captured)
                                    if slot in values else captured)
                    captured_keys.add(slot)
                    pending.append((slot, captured))
        return captured_keys

    def resume_environment(self, function, bound, references, values, state, closure=None):
        """Arguments are captured at creation; globals and cells are read later.

        Refresh only the callee's real module namespace and cells owned by
        this lexical scope. A caller-local spelling is not a callee global,
        and an unrelated caller cannot replace a captured closure binding.
        """
        for key, fact, refs, value in self.global_arguments(function, state):
            bound[key], references[key], values[key] = fact, refs, value
        if closure is not None:
            captured = self.closure_environment(function, state, closure)
            for name, _ref in closure.cells:
                key = f'@free:{name}'
                bound[key] = captured.value(name)
                references[key] = captured.references.get(name, NO_REFERENCES)
                values[key] = captured.bindings.get(name)
            return
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
    def substitute_trace(trace, actual, call_name):
        if trace.parameter is None:
            return frozenset({trace})
        if _INCOMPLETE_PROOF in trace.sanitizers:
            actual = _Flow.incomplete_result(actual)
        for sanitizer in trace.sanitizers - {_INCOMPLETE_PROOF}:
            actual = _sanitize(actual, sanitizer)
        steps = trace.path[1:] if trace.parameter.startswith('@') else trace.path
        return _advance(actual, call_name, *steps)

    @staticmethod
    def incomplete_result(fact):
        return frozenset(TaintTrace(trace.source, trace.parameter,
                                    frozenset({_INCOMPLETE_PROOF}), trace.path) for trace in fact)

    def incomplete_call(self, node, function, summary, bound, references, receiver, state, substitute,
                        values=None, cell_map=None):
        """Project observed writes without trusting the unfinished suffix."""
        budget = self.engine.budget
        if summary.cells:
            # An interrupted body can replace or delete an incoming cell.
            # Preserve observations weakly and discard callable/shape proofs.
            mapping = cell_map or {}
            retained = tuple((ref, _CellContents(contents.fact, contents.references, None, None))
                             for ref, contents in summary.cells
                             if not isinstance(ref, str) or ref in mapping)
            self.apply_cells(retained, frozenset(ref for ref, _contents in retained), mapping, state,
                             node, bound, references, values or {},
                             lambda fact: self.incomplete_result(substitute(fact)))
            if state.cells is not None:
                for ref in mapping.values():
                    contents = state.cells.contents.get(ref)
                    if contents is not None:
                        state.put_cell(ref, _CellContents(self.incomplete_result(contents.fact),
                                                         contents.references, None, None),
                                       written=True, weak=True)
        for parameter, written in summary.mutations:
            refs = self._lookup_refs(references, parameter)
            fact = self.incomplete_result(substitute(written))
            budget.spend(len(refs) * (1 + len(fact)))
            self.mutate(refs, fact, state)
        if summary.global_writes:
            self.apply_globals(summary.global_writes, cell_map or {}, state, node,
                               bound, references, values or {},
                               lambda fact: self.incomplete_result(substitute(fact)), weak=True)

        # The optimized binding contains every module global. Possible return
        # aliases need only actual arguments/cells, globals used by this body,
        # and references already observed by a completed context or prefix.
        budget.spend(len(references) + len(summary.mutations)
                     + len(summary.returned_references) + len(summary.yielded_references))
        owner = self.engine.owner(function)
        used = owner.used_names[function]
        keys = dict.fromkeys(name for name in references
                             if not name.startswith('@global:') or name[8:] in used
                             or name[8:] in owner.closure_names)
        keys.update(dict.fromkeys(summary.returned_references))
        keys.update(dict.fromkeys(summary.yielded_references))
        keys.update(dict.fromkeys(name for name, _fact in summary.mutations))
        possible_refs = []
        for name in keys:
            refs = self._lookup_refs(references, name)
            budget.spend(len(refs) + len(bound.get(name, CLEAN))
                         + sum(len(state.heap.get(ref, CLEAN)) for ref in refs))
            fact = self.incomplete_result(join_facts(
                bound.get(name, CLEAN), *(state.heap.get(ref, CLEAN) for ref in refs)))
            budget.spend(len(refs) * (1 + len(fact)))
            self.mutate(refs, fact, state)
            possible_refs.append(refs)
        returned_refs = frozenset().union(*possible_refs)
        budget.spend(sum(len(fact) for fact in bound.values())
                     + sum(len(state.heap.get(ref, CLEAN)) for ref in returned_refs))
        unknown = join_facts(receiver, *bound.values(), substitute(summary.returned),
                             substitute(summary.yielded),
                             *(state.heap.get(ref, CLEAN) for ref in returned_refs))
        self.expression_bindings[node] = None
        self.expression_references[node] = returned_refs | frozenset({node})
        raised = self.incomplete_result(join_facts(*(substitute(item.value) for item in summary.exceptions)))
        if raised:
            self.observed_raises.append((raised, NO_REFERENCES))
            self.pending.append(_Completion('raise', state.copy(), raised))
        self.possible_exception(state)
        unknown = self.incomplete_result(unknown)
        if function in self.engine.generators:
            # yield-from reads StopIteration.value through a separate channel.
            # An unfinished generator proves neither channel clean or absent.
            self.generator_returns[node] = unknown
            self.generator_return_references[node] = self.expression_references[node]
            self.generator_return_bindings[node] = None
        return unknown

    @classmethod
    def substitute(cls, fact, bound, call_name, *, budget=None):
        if not fact:
            return CLEAN
        if budget is not None:
            # Charge the actual expansion, including parameter substitutions.
            # A single call can carry many transitive sink/mutation facts.
            budget.spend(len(fact) + sum(len(bound.get(trace.parameter, CLEAN))
                                        for trace in fact if trace.parameter is not None))
        return join_facts(*(cls.substitute_trace(trace, bound.get(trace.parameter, CLEAN), call_name)
                            for trace in fact))

    # maps one summary binding into the caller: binding, bound arguments, references, node, call name and values; a parameter record is bead ultimate_bug_scanner-8tqg — ubs:ignore[py.functions.high-param-count]
    def substitute_binding(self, binding, bound, references, node, call_name, values, *, substitute=None,
                           cells=None):
        if binding is None:
            return None
        if substitute is None:
            substitute = _CallSubstitution(self.substitute_trace, bound, call_name, self.engine.budget)
        choices = []
        for target in _binding_choices(binding):
            if isinstance(target, _ClosureValue):
                cell_map = cells or {}
                choices.append(_ClosureValue(
                    self.substitute_binding(target.value, bound, references, node, call_name, values,
                                            substitute=substitute, cells=cells),
                    tuple((name, cell_map.get(ref, ref)) for name, ref in target.cells)))
            elif isinstance(target, _SymbolicValue):
                choices.append(values.get(target.parameter))
            elif isinstance(target, _ArgumentVector):
                operands = []
                element_references = []
                self.engine.budget.spend(len(target.operands)
                                         + sum(len(refs) for refs in target.references))
                for index, (operand, fact) in enumerate(target.operands):
                    if isinstance(operand, _SymbolicValue):
                        replacement = values.get(operand.parameter)
                        if isinstance(replacement, (_LiteralString, _SymbolicValue, frozenset)):
                            operand = _literal_choices(replacement)
                    operands.append((operand, substitute(fact)))
                    refs = frozenset().union(*(
                        self._lookup_refs(references, ref) if isinstance(ref, str) else frozenset({node})
                        for ref in target.references_at(index)))
                    self.engine.budget.spend(len(refs))
                    element_references.append(refs)
                choices.append(_ArgumentVector(tuple(operands), tuple(element_references)))
            elif isinstance(target, _BoundCallable):
                actual = frozenset().union(*(self._lookup_refs(references, ref) if isinstance(ref, str)
                                             else frozenset({node}) for ref in target.references))
                choices.append(_BoundCallable(target.name, actual, substitute(target.receiver), target.namespace_proven))
            elif isinstance(target, _BoundClassMethod):
                actual = frozenset().union(*(
                    self._lookup_refs(references, ref) if isinstance(ref, str)
                    else frozenset({ref if isinstance(ref, ast.ClassDef) else node})
                    for ref in target.references))
                function = self.substitute_binding(target.function, bound, references, node, call_name,
                                                   values, substitute=substitute, cells=cells)
                choices.append(_BoundClassMethod(function, target.owner, actual,
                                                 substitute(target.receiver), target.valid))
            elif isinstance(target, (_DeferredCall, _FunctionValue)):
                arguments = tuple((name, substitute(fact))
                                  for name, fact in target.arguments)
                actual = tuple((name, frozenset().union(*(
                    self._lookup_refs(references, ref) if isinstance(ref, str) else frozenset({node})
                    for ref in refs))) for name, refs in target.references)
                captured_values = tuple((name, self.substitute_binding(value, bound, references,
                                                                       node, call_name, values,
                                                                       substitute=substitute, cells=cells))
                                        for name, value in target.values)
                choices.append(type(target)(target.function, target.call, arguments, actual, captured_values,
                                              tuple((name, (cells or {}).get(ref, ref)) for name, ref in target.cells))
                               if isinstance(target, _DeferredCall)
                               else type(target)(target.function, arguments, actual, captured_values))
            else:
                choices.append(target)
        return _join_bindings(*choices)

    def command_operand(self, node, fact):
        if isinstance(node, (ast.Starred, _ArgumentExpansion)):
            return _ArgumentExpansion(), fact
        literal = self.expression_bindings.get(node)
        if literal == 'sys.executable':
            literal = _LiteralString('python')
        literal = _literal_choices(literal)
        return (literal if isinstance(literal, (_LiteralString, _GeneratorString, _SymbolicValue, frozenset)) else node), fact

    def command_vector(self, node):
        """Expand literal argv without evaluating any argument a second time."""
        binding = self.expression_bindings.get(node)
        self.require_value(binding)
        if isinstance(binding, _ArgumentVector):
            return binding
        if not isinstance(node, (ast.List, ast.Tuple)):
            return None
        result, references = [], []
        for item in node.elts:
            expanded = self.command_vector(item.value) if isinstance(item, ast.Starred) else None
            if expanded is not None:
                result.extend(expanded.operands)
                references.extend(expanded.references if expanded.references else
                                  (self.expression_references.get(item.value, NO_REFERENCES)
                                   for _ in expanded.operands))
            else:
                result.append(self.command_operand(item, self.expression_facts.get(item, CLEAN)))
                references.append(self.expression_references.get(item, NO_REFERENCES))
        self.engine.budget.spend(len(result) + sum(len(refs) for refs in references))
        return _ArgumentVector(tuple(result), tuple(references))

    def command_operands(self, node):
        vector = self.command_vector(node)
        return list(vector.operands) if vector is not None else None

    def command_vectors(self, node):
        binding = self.expression_bindings.get(node)
        self.require_value(binding)
        if isinstance(binding, (frozenset, _ArgumentVector)):
            vectors = [list(value.operands) if isinstance(value, _ArgumentVector) else None
                       for value in _binding_choices(binding)]
        else:
            vectors = [self.command_operands(node)]
        result = []
        for operands in vectors:
            if not operands:
                result.append(operands)
                continue
            for index, (operand, fact) in enumerate(operands):
                result.extend([(program, fact), *operands[index + 1:]]
                              for program in _binding_choices(operand))
                # An unknown expansion can be empty. Each following operand
                # up to the first definite one may therefore be argv[0].
                if not isinstance(operand, _ArgumentExpansion):
                    break
        return result

    def vector_subscript(self, node, state):
        """Project evaluated operands, never the syntax slots before a star.

        A lookup observes index-expression mutations. A slice copies the outer
        container, while selected mutable elements retain conservative aliases.
        """
        binding = self.expression_bindings.get(node.value)
        self.require_value(binding)
        receiver_refs = self.expression_references.get(node.value, NO_REFERENCES)
        vectors = _binding_choices(binding)
        if (receiver_refs & state.mutated or not vectors
                or any(not isinstance(vector, _ArgumentVector) for vector in vectors)):
            return None

        def integer(expression):
            if isinstance(expression, ast.Constant) and isinstance(expression.value, int):
                return expression.value
            if (isinstance(expression, ast.UnaryOp) and isinstance(expression.op, (ast.UAdd, ast.USub))
                    and isinstance(expression.operand, ast.Constant)
                    and isinstance(expression.operand.value, int)):
                return (-expression.operand.value if isinstance(expression.op, ast.USub)
                        else expression.operand.value)
            return _MISSING

        sliced = isinstance(node.slice, ast.Slice)
        if sliced:
            bounds = [None if part is None else integer(part)
                      for part in (node.slice.lower, node.slice.upper, node.slice.step)]
            if _MISSING in bounds or bounds[2] == 0:
                return None
            selector = slice(*bounds)
        else:
            selector = integer(node.slice)

        facts, values, references = [], [], set()
        for vector in vectors:
            operands = vector.operands
            if sliced:
                if any(isinstance(operand, _ArgumentExpansion) for operand, _fact in operands):
                    return None
                selected = range(len(operands))[selector]
            elif selector is _MISSING:
                # The index chooses from these values; its taint cannot create
                # new executable text outside an exact literal whitelist.
                if any(isinstance(operand, _ArgumentExpansion) for operand, _fact in operands):
                    return None
                selected = range(len(operands))
            else:
                if not -len(operands) <= selector < len(operands):
                    return None
                prefix = operands[:selector + 1] if selector >= 0 else operands[selector:]
                if any(isinstance(operand, _ArgumentExpansion) for operand, _fact in prefix):
                    return None
                selected = (selector,)
            self.engine.budget.spend(len(selected))
            projected, projected_references = [], []
            for index in selected:
                operand, fact = operands[index]
                value = (operand if isinstance(operand, (_LiteralString, _SymbolicValue, frozenset))
                         else self.expression_bindings.get(operand))
                immutable = (isinstance(operand, ast.Constant)
                             or all(isinstance(choice, _LiteralString) for choice in _binding_choices(value)))
                refs = (NO_REFERENCES if immutable else receiver_refs | (
                    vector.references_at(index) if vector.references else
                    self.expression_references.get(operand, NO_REFERENCES)))
                self.engine.budget.spend(len(refs) + sum(len(state.heap.get(ref, CLEAN)) for ref in refs))
                fact = join_facts(fact, *(state.heap.get(ref, CLEAN) for ref in refs))
                if refs & state.mutated:
                    value = _without_object_contract(value)
                facts.append(fact)
                references.update(refs)
                if sliced:
                    projected.append((operand, fact))
                    projected_references.append(refs)
                else:
                    values.append(value)
            if sliced:
                values.append(_ArgumentVector(tuple(projected), tuple(projected_references)))
                references.add(node)
        return (join_facts(self.source(node, state), *facts),
                _join_bindings(*values), frozenset(references))

    def require_value(self, binding):
        for value in _binding_choices(binding):
            if isinstance(value, _SymbolicValue):
                self.value_parameters.add(value.parameter)

    def literal_value(self, node):
        binding = self.expression_bindings.get(node, node)
        self.require_value(binding)
        return _literal_text(binding) or _literal_text(node)

    def interpreter_name(self, node):
        binding = self.expression_bindings.get(node)
        if binding == 'sys.executable':
            return 'python'
        return self.literal_value(node)

    def process_input(self, node, program, operands, keyword_nodes, *, shell=False):
        """Remember only processes whose explicit stdin pipe accepts source.

        A communicate() spelling alone is not a process sink. The identity
        follows the process or its bound method, including local returns.
        """
        program = self.interpreter_name(program)
        kind = _interpreter_kind(program)
        pipe = keyword_nodes.get('stdin')
        piped = any(value == 'subprocess.PIPE' or (
            isinstance(value, _BoundCallable) and value.namespace_proven
            and value.name == 'subprocess.PIPE')
            for value in _binding_choices(self.expression_bindings.get(pipe))) or (
            isinstance(pipe, ast.UnaryOp) and isinstance(pipe.op, ast.USub)
            and isinstance(pipe.operand, ast.Constant) and pipe.operand.value == 1)
        if shell or not piped:
            return None
        if program is None:
            # Match immediate input= analysis: a clean but unresolved program
            # can consume source, and shell quoting cannot certify its domain.
            return _ProcessInput('unknown')
        if kind is not None and _interpreter_reads_stdin(kind, operands, self.literal_value):
            return _ProcessInput(kind)
        return None

    def interpreter_effects(self, program_node, operands, stdin=CLEAN):
        program = self.interpreter_name(program_node)
        kind = _interpreter_kind(program)
        if program is None:
            # Clean provenance alone does not identify the selected program.
            # An unresolved executable can be an interpreter, including one
            # built by string operations, so its argv/stdin are not proven data.
            return CLEAN, join_facts(*(fact for _operand, fact in operands), stdin)
        if kind is None:
            return CLEAN, CLEAN
        shell, raw = _interpreter_inputs(kind, operands, self.literal_value)
        if stdin and _interpreter_reads_stdin(kind, operands, self.literal_value):
            if kind == 'shell':
                shell = join_facts(shell, stdin)
            else:
                raw = join_facts(raw, stdin)
        return shell, raw

    def command_effect(self, node, executable, shell_code=CLEAN, interpreter_code=CLEAN):
        # Keep domains separate until concrete call-site substitution. A
        # symbolic executable may bind clean while shell code binds quoted;
        # combining them here would incorrectly revoke shell sanitization.
        self.effect('command', node, 'subprocess executable', executable)
        self.effect('command', node, 'interpreter source', interpreter_code)
        self.effect('command', node, 'subprocess execution', shell_code)

    def partial_value(self, node, state, inputs):
        """Capture a resolved stdlib partial without executing its target."""
        positions = self.call_positions(node, inputs.arguments, state)
        if (not positions or any(isinstance(item[0], (ast.Starred, _ArgumentExpansion))
                                 for item in positions) or None in inputs.keywords):
            raise AnalysisLimit('functools.partial argument expansion needs binding analysis; '
                                'analysis is incomplete')
        captured = [('target', *positions[0])]
        captured.extend((f'pos:{index}', *item) for index, item in enumerate(positions[1:]))
        captured.extend((f'kw:{name}', expression, inputs.keywords[name],
                         self.expression_bindings.get(expression),
                         self.expression_references.get(expression, NO_REFERENCES))
                        for name, expression in sorted(inputs.keyword_nodes.items()))
        arguments, references, values = [], [], []
        for slot, expression, fact, binding, refs in captured:
            self.engine.budget.spend(1 + len(fact) + len(refs))
            if any(value == 'functools.Placeholder' for value in _binding_choices(binding)):
                raise AnalysisLimit('functools.partial Placeholder needs positional binding analysis; '
                                    'analysis is incomplete')
            # Unlike a variable name, a literal scalar option is an evaluated
            # snapshot. Retain bool/None as well as the existing string proof.
            if isinstance(expression, ast.Constant) and binding is None:
                binding = expression
            arguments.append((slot, fact))
            references.append((slot, refs))
            values.append((slot, binding))
        self.expression_bindings[node] = _PartialValue(node, tuple(arguments), tuple(references), tuple(values))
        self.expression_references[node] = frozenset({node})
        self.possible_exception(state)
        return CLEAN

    def invoke_partial(self, node, state, partial, inputs):
        """Invoke captured operands followed by new positional/keyword values.

        Call views have stable identities but never re-evaluate the original
        expressions. Scalar facts stay captured; object aliases and the target
        function's closure cells observe writes performed before invocation.
        """
        if (any(isinstance(argument, ast.Starred) for argument in node.args)
                or None in inputs.keywords):
            raise AnalysisLimit('functools.partial call expansion needs binding analysis; '
                                'analysis is incomplete')
        partial = self.refresh_function_defaults(partial, state.heap, state.mutated)
        facts, refs, values = dict(partial.arguments), dict(partial.references), dict(partial.values)
        slots = [slot for slot, _fact in partial.arguments if slot.startswith('pos:')]
        keywords = {slot[3:]: slot for slot, _fact in partial.arguments if slot.startswith('kw:')}
        for binding in values.values():
            self.require_value(binding)
        # Literal options can change dispatch (e.g. shell=False). Include only
        # their finite identities in the call-view key, never taint evidence.
        shape = tuple((slot, value if isinstance(value, (ast.Constant, _LiteralString)) else None)
                      for slot, value in partial.values if slot != 'target')
        key = (node, partial.function, shape)
        view = self.engine.partial_calls.get(key)
        if view is None:
            expressions = {}
            for slot, value in shape:
                expression = (ast.Constant(value=value.value)
                              if isinstance(value, (ast.Constant, _LiteralString)) else
                              ast.Name(id='@partial:' + slot, ctx=ast.Load()))
                expressions[slot] = ast.copy_location(expression, node)
            call = ast.copy_location(ast.Call(
                func=node.func, args=[*(expressions[slot] for slot in slots), *node.args],
                keywords=[*(ast.keyword(arg=name, value=expressions[slot])
                            for name, slot in keywords.items() if name not in inputs.keywords),
                          *node.keywords]), node)
            view = (call, expressions)
            self.engine.partial_calls[key] = view
        call, expressions = view
        for slot, expression in expressions.items():
            self.expression_facts[expression] = facts[slot]
            self.expression_references[expression] = refs.get(slot, NO_REFERENCES)
            self.expression_bindings[expression] = values.get(slot)
        combined = _CallInputs(
            [*(facts[slot] for slot in slots), *inputs.arguments],
            {**{name: facts[slot] for name, slot in keywords.items()}, **inputs.keywords},
            {**{name: expressions[slot] for name, slot in keywords.items()}, **inputs.keyword_nodes})
        branches, results, returned_refs, bindings = [], [], [], []
        for target in _binding_choices(values.get('target')):
            branch = state.copy()
            self.expression_bindings.pop(call, None)
            self.expression_references.pop(call, None)
            result = self.invoke(call, branch, _CallTarget(
                target, receiver=facts.get('target', CLEAN),
                references=refs.get('target', NO_REFERENCES)), combined)
            if branch.reachable:
                branches.append(branch)
                results.append(result)
                returned_refs.append(self.expression_references.get(call, frozenset({node})))
                bindings.append(self.expression_bindings.get(call))
        state.replace(_join_states(*branches))
        self.expression_bindings[node] = _join_bindings(*bindings)
        self.expression_references[node] = frozenset().union(*returned_refs)
        for table in (self.generator_returns, self.generator_return_references, self.generator_return_bindings):
            if call in table:
                table[node] = table[call]
        return join_facts(*results)

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
                    if isinstance(node.func, ast.Attribute) else frozenset(
                        trace for trace in self.expression_facts.get(node.func, CLEAN)
                        if _INCOMPLETE_PROOF in trace.sanitizers))
        receiver_refs = (self.expression_references.get(node.func.value, NO_REFERENCES)
                         if isinstance(node.func, ast.Attribute) else NO_REFERENCES)
        first = self.immediate_next(node, state, binding)
        if first is not _MISSING:
            if original is not node:
                for values in (self.expression_references, self.expression_bindings):
                    if node in values:
                        values[original] = values[node]
                    else:
                        values.pop(original, None)
            return first
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
            result = self.invoke(node, branch, _CallTarget(target, fallback_name, receiver, receiver_refs),
                                 _CallInputs(arguments, keywords, keyword_nodes))
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

    def invoke(self, node, state, callee, inputs, *, resumed=None):
        target, fallback_name = callee.binding, callee.fallback_name
        receiver, receiver_refs = callee.receiver, callee.references
        arguments, keywords, keyword_nodes = inputs.arguments, inputs.keywords, inputs.keyword_nodes
        if (target in {'next', 'builtins.next'} and any(
                engine.generator_builtin_reflection or engine.generator_literal_authority_exposed
                or engine.generator_namespace_exposed
                or engine.generator_frame_exposed or 'next' in engine.generator_attribute_writes
                for engine in self.engine.generator_peers)):
            # A builtin-qualified spelling can outlive replacement of the
            # native callable. Opaque fallback only propagates argument data
            # and would miss a replacement that returns a fresh source.
            raise AnalysisLimit('generator next consumer identity is unresolved; analysis is incomplete')
        if self.materialized_generator_depth and not self.materialized_generator_call(node, target, state):
            raise AnalysisLimit('generator materialization helper frame lifetime is unresolved; analysis is incomplete')
        if isinstance(target, _GeneratorNext):
            if node.args or node.keywords:
                raise AnalysisLimit('generator __next__ argument binding; analysis is incomplete')
            generator = dict(target.values).get(_GENERATOR_CURSOR)
            if not isinstance(generator, _DeferredGenerator):
                raise AnalysisLimit('generator method lost its cursor; analysis is incomplete')
            return self.next_generator(node, state, generator)
        if isinstance(target, _DeferredGenerator):
            raise AnalysisLimit('generator called as a function; analysis is incomplete')
        for expression in (*(node.args if isinstance(node, ast.Call) else ()), *keyword_nodes.values()):
            if any(isinstance(value, (_DeferredGenerator, _GeneratorNext))
                   for value in _binding_choices(self.expression_bindings.get(expression))):
                raise AnalysisLimit('generator passed to an unmodeled consumer; analysis is incomplete')
        if isinstance(target, _PartialValue):
            return self.invoke_partial(node, state, target, inputs)
        if target == _PARTIAL_CHANGED_CONSTRUCTOR:
            raise AnalysisLimit('functools.partial constructor replacement; analysis is incomplete')
        if isinstance(target, _GlobalNamespace):
            if target.module is not self.engine.tree:
                raise AnalysisLimit('foreign globals mapping call; analysis is incomplete')
            if target.member == 'update':
                for expression in node.args:
                    if not isinstance(expression, ast.Dict):
                        raise AnalysisLimit('opaque globals mapping update; analysis is incomplete')
                    for key, value in zip(expression.keys, expression.values):
                        if key is None:
                            raise AnalysisLimit('expanded globals mapping update; analysis is incomplete')
                        self.write_global(target, key, self.expression_facts.get(value, CLEAN), value, state)
                for name, expression in keyword_nodes.items():
                    if name is None:
                        raise AnalysisLimit('expanded globals mapping update; analysis is incomplete')
                    key = ast.Constant(value=name)
                    self.write_global(target, key, keywords[name], expression, state)
                self.expression_bindings[node] = None
                self.expression_references[node] = NO_REFERENCES
                return CLEAN
            if target.member == 'get' and node.args:
                fact, value, refs, present = self.read_global(target, node.args[0], state)
                if not present and len(node.args) > 1:
                    fact = join_facts(fact, arguments[1])
                    value = _join_bindings(value, self.expression_bindings.get(node.args[1]))
                    refs |= self.expression_references.get(node.args[1], NO_REFERENCES)
                self.expression_bindings[node], self.expression_references[node] = value, refs
                return fact
            raise AnalysisLimit('unsupported globals mapping method; analysis is incomplete')
        if target in ('globals', 'builtins.globals'):
            if node.args or node.keywords:
                self.possible_exception(state)
                return CLEAN
            self.expression_bindings[node] = _GlobalNamespace(self.engine.tree)
            self.expression_references[node] = NO_REFERENCES
            return CLEAN
        # Summary heap mutations carry value facts, not replacements of a
        # module's callable cells. Never lose that write authority by turning
        # an escaping globals mapping into an ordinary symbolic parameter.
        # Await resumes reuse arguments checked when the coroutine was
        # created; the Await node has no new argument expressions.
        for expression in (*(node.args if isinstance(node, ast.Call) else ()), *keyword_nodes.values()):
            if any(isinstance(value, _GlobalNamespace)
                   for value in _binding_choices(self.expression_bindings.get(expression))):
                raise AnalysisLimit('globals mapping passed to a callable; analysis is incomplete')
        if isinstance(target, _BoundClassMethod):
            function = target.function.function if isinstance(target.function, (_ClosureValue, _FunctionValue)) else target.function
            signature = function.args
            positional = [arg.arg for arg in (*signature.posonlyargs, *signature.args)]
            count = len(node.args) + 1
            expanded = any(isinstance(arg, ast.Starred) for arg in node.args)
            named = set(keyword_nodes) - {None}
            accepted = {arg.arg for arg in (*signature.args, *signature.kwonlyargs)}
            definite_mismatch = (
                not expanded and signature.vararg is None and count > len(positional)
                or signature.kwarg is None and bool(named - accepted)
                or not expanded and bool(named & set(positional[len(signature.posonlyargs):count]))
            )
            if not expanded and None not in keyword_nodes:
                required = positional[:len(positional) - len(signature.defaults)]
                definite_mismatch |= count < min(len(signature.posonlyargs), len(required))
                definite_mismatch |= any(name not in named for name in required[max(count, len(signature.posonlyargs)):])
                definite_mismatch |= any(arg.arg not in named for arg, default
                                         in zip(signature.kwonlyargs, signature.kw_defaults) if default is None)
            if definite_mismatch:
                # An unbindable invocation does not establish the callee's
                # clean-return contract. Retain the ordinary opaque-call
                # provenance rather than binding arguments to wrong slots.
                return self.invoke(node, state, _CallTarget(None, receiver=target.receiver, references=target.references),
                                   inputs)
            # This is a call view, not a second evaluation of the receiver or
            # its arguments. Keep its AST identity fixed across worklist passes
            # and recursive/coroutine summaries just like literal * expansion.
            key = (node, target.function, target.owner)
            call = self.engine.method_calls.get(key)
            if call is None:
                implicit = ast.copy_location(ast.Name(id='@receiver', ctx=ast.Load()), node)
                call = ast.copy_location(ast.Call(func=node.func, args=[implicit, *node.args],
                                                  keywords=node.keywords), node)
                self.engine.method_calls[key] = call
            implicit = call.args[0]
            refs = target.references
            value = join_facts(target.receiver, *(state.heap.get(ref, CLEAN) for ref in refs))
            self.expression_facts[implicit] = value
            self.expression_references[implicit] = refs
            self.expression_bindings[implicit] = (target.owner if target.valid and not refs & state.mutated else None)
            result = self.invoke(call, state, _CallTarget(target.function),
                                 _CallInputs([value, *arguments], keywords, keyword_nodes))
            for table in (self.expression_bindings, self.expression_references,
                          self.generator_returns, self.generator_return_references,
                          self.generator_return_bindings):
                if call in table:
                    table[node] = table[call]
                else:
                    table.pop(node, None)
            return result
        name = target if isinstance(target, str) else fallback_name if target is None else ''
        if isinstance(target, _BoundCallable):
            name = target.name
            receiver_refs = target.references
            receiver = join_facts(target.receiver, *(state.heap.get(ref, CLEAN) for ref in receiver_refs))
            if name == _LITERAL_MAPPING_GET:
                receiver, unchanged = self.literal_mapping_contents(receiver, receiver_refs, state)
                if (unchanged and 1 <= len(arguments) <= 2 and not keywords
                        and not any(isinstance(argument, ast.Starred) for argument in node.args)):
                    # Evaluate both arguments before applying this transfer:
                    # a key/default expression can mutate the captured dict.
                    if self.literal_mapping_key(node.args[0], state):
                        default = node.args[1] if len(arguments) == 2 else None
                        self.expression_bindings[node] = _join_bindings(
                            None, self.expression_bindings.get(default))
                        self.expression_references[node] = self.expression_references.get(default, NO_REFERENCES)
                        self.possible_exception(state)
                        return join_facts(receiver, arguments[1] if default is not None else CLEAN)
                    # A custom protocol may also affect later reads whose
                    # own keys are primitive. Retain the possible write.
                    self.mutate(receiver_refs, arguments[0], state)
        if name == 'functools.partial':
            return self.partial_value(node, state, inputs)
        value = (self.expression_bindings.get(node.args[0])
                 if isinstance(node, ast.Call) and len(node.args) == 1
                 and isinstance(node.args[0], ast.GeneratorExp) else None)
        choices = _binding_choices(value)
        if (target in {'any', 'all', 'builtins.any', 'builtins.all'}
                and choices and choices <= frozenset(_PREDICATE_RESULTS)):
            # Only the synchronous producer's native-identity proof grants a
            # bool result. A qualified spelling alone can still refer to a
            # replaced builtins member and must retain opaque-call provenance.
            self.expression_bindings[node] = value
            self.expression_references[node] = NO_REFERENCES
            self.possible_exception(state)
            return CLEAN
        closure = target if isinstance(target, _ClosureValue) else None
        if closure is not None:
            target = closure.value
        elif resumed is not None and resumed.cells:
            closure = _ClosureValue(resumed.function, resumed.cells)
        captured_defaults = target if isinstance(target, _FunctionValue) else None
        if captured_defaults is not None:
            target = captured_defaults.function
        if isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            function = target
            call_name = _call_name(function)
            owner = self.engine.owner(function)
            if resumed is None:
                module_ref = owner.project.module_reference(owner) if owner.project is not None else None
                if (owner is self.engine
                        and not isinstance(self.scope, ast.Module)
                        and not self.comprehension_environments
                        and not self.class_environments
                        and (module_ref is None or (module_ref not in state.heap and module_ref not in state.mutated))):
                    local_bound = self.bind(function, node, arguments, keywords, state, (), captured_defaults, closure)
                    local_refs = self.bind_references(function, node, keyword_nodes, state, (), captured_defaults, closure)
                    local_values = self.bind_values(function, node, arguments, keyword_nodes, state, (), captured_defaults, closure)
                    bound = owner.base_global_bound.copy()
                    references = owner.base_global_refs.copy()
                    values = owner.base_global_values.copy()
                    shadowed_vals = owner.shadowed_global_values.get(self.scope)
                    non_base_keys = list(local_values)
                    if state.heap:
                        for hkey, hfact in state.heap.items():
                            if isinstance(hkey, str) and hkey in bound and (not shadowed_vals or hkey not in shadowed_vals):
                                bound[hkey] = join_facts(bound[hkey], hfact)
                    if state.mutated:
                        for mkey in state.mutated:
                            if isinstance(mkey, str) and mkey in values and (not shadowed_vals or mkey not in shadowed_vals):
                                val = values[mkey]
                                if val is not None:
                                    values[mkey] = _without_object_contract(val)
                                    non_base_keys.append(mkey)
                    if shadowed_vals:
                        values.update(shadowed_vals)
                        non_base_keys.extend(shadowed_vals)
                    for gname in owner.active_globals.get(self.scope, ()):
                        gkey = f'@global:{gname}'
                        bound[gkey] = state.value(gname)
                        grefs = state.references.get(gname, NO_REFERENCES)
                        references[gkey] = grefs
                        val = state.bindings.get(gname)
                        if val is not None and state.mutated and grefs and (grefs & state.mutated):
                            val = _without_object_contract(val)
                        values[gkey] = val
                        non_base_keys.append(gkey)
                    for gname in self.context_globals:
                        if shadowed_vals and f'@global:{gname}' in shadowed_vals:
                            continue
                        gkey = f'@global:{gname}'
                        bound[gkey] = state.value(gname)
                        grefs = state.references.get(gname, NO_REFERENCES)
                        references[gkey] = grefs
                        val = state.bindings.get(gname)
                        if val is not None and state.mutated and grefs and (grefs & state.mutated):
                            val = _without_object_contract(val)
                        values[gkey] = val
                        non_base_keys.append(gkey)
                    for gkey in state.bindings:
                        if gkey.startswith(('@global:', '@presence:')):
                            self.engine.budget.spend()
                            bound[gkey] = state.value(gkey)
                            references[gkey] = state.references.get(gkey, NO_REFERENCES)
                            values[gkey] = state.bindings[gkey]
                            non_base_keys.append(gkey)
                    bound.update(local_bound)
                    references.update(local_refs)
                    values.update(local_values)
                    if state.mutated:
                        for name, refs in local_refs.items():
                            if refs and (refs & state.mutated):
                                values[name] = _without_object_contract(values.get(name))
                    receiver_keys = None if owner.has_base_bound_methods else non_base_keys
                    summary_keys = (
                        (*non_base_keys, *(k for k in owner.class_globals if k not in non_base_keys))
                        if owner.class_globals else non_base_keys
                    )
                else:
                    globals_snapshot = tuple(self.global_arguments(function, state))
                    bound = self.bind(function, node, arguments, keywords, state, globals_snapshot, captured_defaults, closure)
                    references = self.bind_references(function, node, keyword_nodes, state, globals_snapshot, captured_defaults, closure)
                    values = self.bind_values(function, node, arguments, keyword_nodes, state, globals_snapshot, captured_defaults, closure)
                    if state.mutated:
                        for name, refs in references.items():
                            if refs and (refs & state.mutated):
                                values[name] = _without_object_contract(values.get(name))
                    receiver_keys = None
                    summary_keys = None
            else:
                references = dict(resumed.references)
                values = dict(resumed.values)
                bound = {name: join_facts(fact, *(state.heap.get(ref, CLEAN)
                                              for ref in self._lookup_refs(references, name)))
                         for name, fact in resumed.arguments}
                self.resume_environment(function, bound, references, values, state, closure)
                if state.mutated:
                    for name, refs in references.items():
                        if refs and (refs & state.mutated):
                            values[name] = _without_object_contract(values.get(name))
                receiver_keys = None
                summary_keys = None
            self.bind_method_receivers(bound, references, values, state, receiver_keys)
            if resumed is None and _terminal_generator(function):
                generator = self.generator_value(captured_defaults or function, node, inputs,
                                                 bound, references, values, state, closure)
                if generator is not None:
                    self.expression_bindings[node] = generator
                    self.expression_references[node] = NO_REFERENCES
                    return CLEAN
            if (isinstance(function, ast.AsyncFunctionDef)
                    and function not in self.engine.generators and resumed is None):
                self.expression_bindings[node] = _DeferredCall(
                    function, node, tuple(sorted(bound.items())), tuple(sorted(references.items())),
                    tuple(sorted(values.items())), closure.cells if closure is not None else ())
                self.expression_references[node] = NO_REFERENCES
                return CLEAN
            overrides = set(self.context_globals) if owner is self.engine else set()
            # A temporary callable replacement must survive intervening
            # helpers even when they do not lexically name that global.
            # Stable raw helper definitions need no transitive context entry.
            for key in summary_keys if summary_keys is not None else values:
                if not owner.namespace_ready:
                    break
                if not key.startswith('@global:'):
                    continue
                gname = key[8:]
                if gname not in owner.rebound_globals:
                    continue
                binding = values.get(key)
                nominal = owner.globals.bindings.get(gname)
                if (isinstance(binding, _SymbolicValue)
                        or _same_witness(binding, nominal)):
                    continue
                if any(isinstance(value, (str, _LiteralString, _GeneratorString, _LiteralMapping, _ArgumentVector, _ProcessInput,
                                          _FunctionValue, _ClosureValue,
                                          ast.FunctionDef, ast.AsyncFunctionDef,
                                          ast.Lambda, ast.Constant, _BoundClassMethod))
                       for value in (*_binding_choices(binding), *_binding_choices(nominal))):
                    overrides.add(gname)
            prepared = []

            def cell_context(required):
                result = self.prepare_cell_context(function, closure, values, state, summary_keys, required)
                prepared[:] = [result]
                return result[:2]

            has_cells = closure is not None or state.cells is not None or owner.globals.cells is not None
            summary = self.engine.call_summary(function, values, summary_keys, overrides,
                                               cell_context=cell_context if has_cells else None)
            cell_map, cell_keys = {}, set()
            if prepared:
                _contextual, _keys, cell_map, cell_bound, cell_refs, cell_values = prepared[0]
                bound.update(cell_bound)
                references.update(cell_refs)
                values.update(cell_values)
                cell_keys = set(cell_values)
                if receiver_keys is not None:
                    receiver_keys = set(receiver_keys) | cell_keys
            self.engine.budget.spend(len(summary.capture_globals))
            self.capture_globals.update(summary.capture_globals)
            captured_keys = self.bind_function_defaults(bound, references, values, state, receiver_keys,
                                                        function=function, summary=summary)
            vector_keys = (None if summary_keys is None else
                           set(summary_keys) | captured_keys | cell_keys | {
                               f'@global:{name}' for module, name in summary.capture_globals if module is owner.tree})
            self.bind_vector_elements(bound, references, values, state, vector_keys)
            for name in summary.value_parameters:
                for value in _binding_choices(values.get(name)):
                    if isinstance(value, _SymbolicValue):
                        self.value_parameters.add(value.parameter)
            substitute = _CallSubstitution(self.substitute_trace, bound, call_name, self.engine.budget)
            for kind, line, column, label, fact in summary.effects:
                propagated = substitute(fact)
                propagated = frozenset(trace for trace in propagated if not _safe_for(trace, kind, label))
                key = (kind, line, column, label)
                if propagated:
                    self.effects[key] = join_facts(self.effects.get(key, CLEAN), propagated)
            if (closure is not None and function in self.engine.generators
                    and summary != FunctionSummary()
                    and not self.stable_generator_receivers(function, closure, state)):
                # Generator summaries currently join the whole body rather
                # than representing suspension/resume program counters. Live
                # cells can change between construction and any later yield;
                # do not certify a snapshot as the value read on resumption.
                # Wait for a non-bottom summary and retain its known effects.
                raise AnalysisLimit('generator with live lexical cells requires resume-state analysis; '
                                    'analysis is incomplete')
            if (function in owner.generators and (summary.global_writes
                    or any(exception.global_writes for exception in summary.exceptions))):
                raise AnalysisLimit('generator global writes require resume-state analysis; analysis is incomplete')
            if (function in owner.generators or self.deferred_generator_depth) and summary != FunctionSummary():
                if self.deferred_generator_depth and closure is not None and closure.cells:
                    raise AnalysisLimit('generator expression helper reads live lexical cells; analysis is incomplete')
                if self.deferred_generator_depth and not owner.generator_helper_identity(function):
                    raise AnalysisLimit('generator expression helper identity may change; analysis is incomplete')
                delayed_globals = set(owner.active_globals.get(function, ()))
                delayed_globals.update(name for module, name in summary.capture_globals if module is owner.tree)
                delayed_globals.update(self.generator_summary_globals(summary))
                if any(not owner.generator_stable_binding(name, owner.tree, node)
                       or self.deferred_generator_depth and not (
                           owner.generator_literal_binding(name)
                           or isinstance(owner.globals.bindings.get(name), (ast.FunctionDef, ast.AsyncFunctionDef,
                                                                            ast.Lambda, _LiteralString)))
                       for name in owner.rebound_globals.intersection(delayed_globals)):
                    raise AnalysisLimit('generator live global reads require resume-state analysis; analysis is incomplete')
            if summary.incomplete:
                # Resumed coroutines use an Await node, not a Call, and their
                # values were captured at construction. Use the already bound
                # environment without evaluating either syntax a second time.
                return self.incomplete_call(node, function, summary, bound, references,
                                            receiver, state, substitute, values, cell_map)
            for exception in summary.exceptions:
                exceptional = state.copy()
                exceptional_cells = cell_map.copy()
                for parameter, written in exception.mutations:
                    self.mutate(self._lookup_refs(references, parameter),
                                substitute(written), exceptional)
                self.apply_cells(exception.cells, exception.multiple_cells, exceptional_cells, exceptional,
                                 node, bound, references, values, substitute)
                self.apply_globals(exception.global_writes, exceptional_cells, exceptional,
                                   node, bound, references, values, substitute)
                raised = substitute(exception.value)
                self.observed_raises.append((raised, frozenset({node})))
                self.pending.append(_Completion(
                    'raise', exceptional, raised,
                    frozenset({node}),
                    '@exception:' + exception.exception_type if exception.exception_type else None,
                    exception.exception_type,
                ))
            if not summary.can_return and function not in self.engine.generators:
                state.reachable = False
                return CLEAN
            # Materialized calls already proved their frame at invoke entry.
            # For captured results, prove it before applying effects. Do not
            # substitute returned handles yet: apply_cells first allocates
            # the caller's distinct generator/closure cells.
            format_frame_inert = (bool(self.materialized_generator_depth) or not any(
                isinstance(value, (_LiteralString, _GeneratorString, _ArgumentVector,
                                   _SymbolicValue, ast.Constant))
                for value in _binding_choices(summary.returned_binding)))
            if not format_frame_inert and isinstance(node, ast.Call):
                format_frame_inert = self.materialized_generator_call(node, target, state)
            for parameter, written in summary.mutations:
                fact = substitute(written)
                self.mutate(self._lookup_refs(references, parameter), fact, state)
            self.apply_cells(summary.cells, summary.multiple_cells, cell_map, state,
                             node, bound, references, values, substitute)
            self.apply_globals(summary.global_writes, cell_map, state,
                               node, bound, references, values, substitute)
            returned_refs = frozenset().union(*(self._lookup_refs(references, parameter)
                                               for parameter in summary.returned_references))
            self.expression_references[node] = returned_refs or frozenset({node})
            returned_binding = self.substitute_binding(
                summary.returned_binding, bound, references, node, call_name, values,
                substitute=substitute, cells=cell_map)
            self.expression_bindings[node] = (returned_binding if format_frame_inert
                                             else self.without_format_authority(returned_binding))
            returned = substitute(summary.returned)
            if function in self.engine.generators:
                self.generator_returns[node] = returned
                self.generator_return_references[node] = returned_refs
                self.generator_return_bindings[node] = self.expression_bindings[node]
                self.expression_bindings[node] = self.substitute_binding(
                    summary.yielded_binding, bound, references, node, call_name, values,
                    substitute=substitute, cells=cell_map)
                self.expression_references[node] = frozenset().union(*(
                    self._lookup_refs(references, parameter) for parameter in summary.yielded_references))
                return substitute(summary.yielded)
            return returned
        deferred = [target for expression in [*node.args, *keyword_nodes.values()]
                    for target in _binding_choices(self.expression_bindings.get(expression))
                    if isinstance(target, _DeferredCall)]
        for expression in (*node.args, *keyword_nodes.values()):
            for value in _binding_choices(self.expression_bindings.get(expression)):
                function = value.function if isinstance(value, (_FunctionValue, _ClosureValue)) else value
                if (isinstance(function, ast.FunctionDef) and _terminal_generator(function)
                        and name not in _DEPENDENCY_MARKERS):
                    raise AnalysisLimit('generator function passed to an unresolved consumer; analysis is incomplete')
        awaitable = node.args[0] if node.args else keyword_nodes.get('main')
        alternatives = _binding_choices(self.expression_bindings.get(awaitable))
        if name == 'asyncio.run' and any(isinstance(item, _DeferredCall) for item in alternatives):
            # run() waits for completion; create_task()/gather() below do not.
            branches, values, returned_bindings, returned_refs = [], [], [], []
            for coroutine in alternatives:
                branch = state.copy()
                if isinstance(coroutine, _DeferredCall):
                    value = self.invoke(node, branch, _CallTarget(coroutine.function),
                                        _CallInputs([], {}, {}), resumed=coroutine)
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
                    self.invoke(node, branch, _CallTarget(coroutine.function),
                                _CallInputs([], {}, {}), resumed=coroutine)
                    ends = [branch, *(item.state for item in self.pending)]
                finally:
                    self.pending = outer
                for end in ends:
                    if end.global_writes != state.global_writes:
                        raise AnalysisLimit('scheduled task global writes require scheduling analysis; '
                                            'analysis is incomplete')
                    for ref in end.heap.keys() | end.mutated:
                        self.mutate(frozenset({ref}), end.heap.get(ref, CLEAN), state)
                    if end.cells is not None:
                        for ref in end.cells.written:
                            state.put_cell(ref, end.cells.contents[ref], written=True, weak=True)
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
        elif name in _HTTP_URL_POSITIONS:
            position = _HTTP_URL_POSITIONS[name]
            # The call view already expands literal *lists and *tuples. An
            # opaque expansion before the URL can shift later arguments, so
            # retain every possible URL rather than trusting the old offset.
            # An expansion after an explicit URL cannot change that operand.
            star = next((index for index, argument in enumerate(node.args)
                         if index <= position and isinstance(argument, ast.Starred)), None)
            if star is not None:
                destination = join_facts(*arguments[star:], keywords.get('url', CLEAN),
                                         keywords.get(None, CLEAN))
            elif len(arguments) > position:
                destination = arguments[position]
            else:
                destination = join_facts(keywords.get('url', CLEAN), keywords.get(None, CLEAN))
            # Share the site key across callable alternatives: a joined
            # requests.get/httpx.get target is one reachable network sink.
            self.effect('ssrf', node, 'HTTP request URL', destination)
        elif name in {'subprocess.run', 'subprocess.Popen', 'subprocess.call', 'subprocess.check_output', 'subprocess.check_call'}:
            command_fact = source_argument('args')
            command_node = node.args[0] if node.args else keyword_nodes.get('args')
            shell = keyword_nodes.get('shell')
            shell_true = isinstance(shell, ast.Constant) and bool(shell.value)
            shell_unknown = (shell is not None and not isinstance(shell, ast.Constant)) or None in keywords
            explicit_executable = join_facts(keywords.get('executable', CLEAN), keywords.get(None, CLEAN))
            executable_node = keyword_nodes.get('executable')
            executable_value, _fact = self.command_operand(executable_node, explicit_executable)
            has_override = executable_node is not None and not (
                isinstance(executable_node, ast.Constant) and executable_node.value is None)
            executable, shell_code, interpreter_code = explicit_executable, CLEAN, CLEAN
            process_inputs = []
            stdin = keywords.get('input', CLEAN) if leaf in {'run', 'check_output'} else CLEAN
            # Keep each program/argv alternative paired. Combining the first
            # item of one branch with tainted data from another invents flows.
            for operands in self.command_vectors(command_node):
                command = (operands[0][1] if operands else CLEAN) if operands is not None else command_fact
                for override in _binding_choices(executable_value):
                    override_name = self.interpreter_name(override)
                    fixed_executable = (isinstance(override, _LiteralString)
                                        or isinstance(override, ast.Constant) and override.value is not None)
                    if (not shell_true or shell_unknown) and not fixed_executable:
                        executable = join_facts(executable, command)
                    if shell_true or shell_unknown:
                        shell_code = join_facts(shell_code, command)
                        if has_override and _interpreter_kind(override_name) != 'shell':
                            interpreter_code = join_facts(interpreter_code, command)
                    process = None
                    if not shell_true or shell_unknown:
                        program_node = override if fixed_executable else operands[0][0] if operands else command_node
                        tail = operands[1:] if operands else []
                        if operands is not None or self.interpreter_name(command_node) is not None:
                            nested_shell, nested_raw = self.interpreter_effects(program_node, tail, stdin)
                            shell_code = join_facts(shell_code, nested_shell)
                            interpreter_code = join_facts(interpreter_code, nested_raw)
                        else:
                            # Opaque argv cannot establish a data-only stdin
                            # mode, even with a fixed interpreter override.
                            tail = [(_ArgumentExpansion(), command_fact)]
                            if _interpreter_kind(self.interpreter_name(program_node)) is not None:
                                interpreter_code = join_facts(interpreter_code, command_fact, stdin)
                        process = self.process_input(node, program_node, tail, keyword_nodes)
                    if has_override and not fixed_executable:
                        # An unresolved override may itself select an interpreter;
                        # its clean provenance is not proof that argv is data.
                        interpreter_code = join_facts(interpreter_code, command_fact, stdin)
                        if not shell_true or shell_unknown:
                            process = self.process_input(node, None, [], keyword_nodes)
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
        elif name in {'@stdin.shell', '@stdin.python', '@stdin.unknown'}:
            code = source_argument('input')
            self.command_effect(node, CLEAN, code if name == '@stdin.shell' else CLEAN,
                                code if name != '@stdin.shell' else CLEAN)
        else:
            # Passing a known vector to an unmodeled routine may mutate it.
            # Retain aggregate provenance but stop certifying its old shape.
            # This effect is summarized even for a symbolic helper parameter.
            for expression in (*node.args, *keyword_nodes.values()):
                value = self.expression_bindings.get(expression)
                self.escape_literal_mapping(value, self.expression_references.get(expression, NO_REFERENCES), state)
                if {'functools', _PARTIAL_CHANGED_MODULE} & _binding_choices(value) and name not in {
                        'print', 'str', 'repr', 'bool', 'builtins.print', 'builtins.str', 'builtins.repr'}:
                    self.mutate(frozenset({_PARTIAL_MODULE_REF}), CLEAN, state)
                if any(isinstance(choice, (_ArgumentVector, _SymbolicValue, ast.ClassDef, _BoundClassMethod))
                       for choice in _binding_choices(value)) and name not in SANITIZERS and name not in {
                           'print', 'str', 'len', 'repr', 'tuple', 'list', 'bool', 'int', 'float',
                           'builtins.print', 'builtins.str', 'builtins.len', 'builtins.repr'}:
                    self.mutate(self.expression_references.get(expression, NO_REFERENCES), CLEAN, state)
                    for choice in _binding_choices(value):
                        if isinstance(choice, _BoundClassMethod):
                            self.mutate(choice.references, CLEAN, state)
        # A native sink contract describes its data operands, not arbitrary
        # callbacks such as subprocess preexec_fn or HTTP authentication.
        # Keep any observed sink effect, then refuse unmodeled partial escapes.
        if name not in {'print', 'str', 'repr', 'bool', 'builtins.print', 'builtins.str', 'builtins.repr'}:
            for expression in (*node.args, *keyword_nodes.values()):
                if any(isinstance(value, _PartialValue)
                       for value in _binding_choices(self.expression_bindings.get(expression))):
                    raise AnalysisLimit('functools.partial passed to an unresolved consumer; analysis is incomplete')
        configurable_html = name == 'bleach.clean' and (
            len(node.args) > 1 or any(keyword.arg not in {'text', 'strip', 'strip_comments'} for keyword in node.keywords)
        )
        if name in SANITIZERS and not configurable_html:
            fact = _sanitize(fact, SANITIZERS[name])
        if callee.binding in {'input', 'builtins.input'} and self.generator_builtins_stable():
            # Retain this type proof with the evaluated value. Looking up an
            # old call AST later could instead observe a rebound input name.
            self.expression_bindings[node] = _GeneratorString(format_safe=(
                len(node.args) <= 1 and not node.keywords
                and all(self.formatted_string_operand(argument, state) for argument in node.args)))
        if not exception_constructor:
            self.possible_exception(state)
        return fact

    def expr(self, node, state):
        if node is None or not state.reachable:
            return CLEAN
        self.engine.budget.spend()
        if isinstance(node, ast.Constant):
            self.expression_references.pop(node, None)
            self.expression_bindings[node] = (_LiteralString(node.value) if isinstance(node.value, str)
                                             else node if isinstance(node.value, bool) else None)
            self.expression_facts[node] = CLEAN
            return CLEAN
        if isinstance(node, ast.Name):
            if state.cells is not None and node.id in state.cells.names:
                contents = state.cells.contents[state.cells.names[node.id]]
                if contents.bound is not True:
                    self.pending.append(_Completion('raise', state.copy(), exception_type='NameError'))
                    if contents.bound is False:
                        state.reachable = False
                        return CLEAN
            fact = state.value(node.id)
            self.expression_facts[node] = fact
            binding = state.bindings.get(node.id, _implicit_identity(node.id))
            slot = '@global:' + node.id
            shadowed = self.global_shadowed(node.id)
            if not shadowed and slot in state.bindings:
                fact = state.value(slot)
                binding = state.bindings[slot]
                self.expression_facts[node] = fact
            if (node.id in self.engine.global_names
                    and node.id not in self.engine.locals.get(self.scope, ())
                    and node.id not in self.engine.closures.get(self.scope, ())
                    and not any(node.id in self.engine.locals[scope]
                                for scope, _outer in self.comprehension_environments)):
                # Classes and captured callable values can be rebound through
                # a helper. Unchanged raw helper definitions do not need an
                # ever-growing transitive dependency set along call chains.
                nominal = self.engine.globals.bindings.get(node.id)
                nominal_helper = (isinstance(binding, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
                                  and binding is self.engine.globals.bindings.get(node.id)
                                  and getattr(binding, 'name', None) == node.id
                                  and node.id not in self.engine.rebound_globals
                                  and node.id not in self.context_globals)
                identity = (str, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                            ast.ClassDef, _FunctionValue, _ClosureValue, _BoundCallable,
                            _BoundClassMethod, _ModuleBinding, _ArgumentVector, _LiteralString, _GeneratorString, _LiteralMapping,
                            _ProcessInput, ast.Constant)
                if (not nominal_helper and any(isinstance(value, identity)
                        for value in (*_binding_choices(binding), *_binding_choices(nominal)))):
                    self.capture_globals.add((self.engine.tree, node.id))
            refs = state.references.get(slot if not shadowed and slot in state.bindings else node.id, NO_REFERENCES)
            self.expression_references[node] = refs
            if state.mutated and (refs & state.mutated):
                binding = _without_object_contract(binding)
            self.expression_bindings[node] = binding
            if self.materialized_generator_depth:
                parent = self.engine.parents.get(node)
                is_callee = isinstance(parent, ast.Call) and parent.func is node
                if (isinstance(parent, ast.Attribute) and parent.value is node
                        and isinstance(self.engine.parents.get(parent), ast.Call)
                        and self.engine.parents[parent].func is parent
                        and binding == 'builtins' and node.id in self.engine.generator_readonly_builtins):
                    is_callee = True
                if not is_callee and not self.materialized_generator_binding(binding, refs, state):
                    # A primitive final result is insufficient: an earlier
                    # truth test, index, format or discarded operand can have
                    # invoked an opaque object's protocol along the way.
                    raise AnalysisLimit('generator materialization reads an opaque operand; analysis is incomplete')
            if any(isinstance(value, (_DeferredGenerator, _GeneratorNext)) for value in _binding_choices(binding)):
                parent = self.engine.parents.get(node)
                if isinstance(parent, (ast.withitem, ast.AugAssign, ast.Match, ast.ClassDef)):
                    raise AnalysisLimit('generator used by an unmodeled statement protocol; analysis is incomplete')
            return fact
        # Callable identity belongs to the point before its arguments execute:
        # Query(alias := other) still constructs the originally bound marker.
        is_call = isinstance(node, ast.Call)
        imported_call = _imported_name(node.func, state.bindings) if is_call else ''
        exception_type = self.exception_type(node.func, state) if is_call else None
        may_raise = isinstance(node, (ast.Attribute, ast.Subscript,
                                      ast.BinOp, ast.Compare, ast.UnaryOp))
        if may_raise and self.exception_states:
            self.possible_exception(state)
        self.expression_references.pop(node, None)
        self.expression_bindings.pop(node, None)
        fact = self.expression(node, state)
        if not state.reachable:
            return CLEAN
        if not isinstance(node, (ast.Call, ast.Attribute, ast.NamedExpr, ast.IfExp, ast.BoolOp)):
            if any(isinstance(value, (_DeferredGenerator, _GeneratorNext))
                   for child in ast.iter_child_nodes(node)
                   for value in _binding_choices(self.expression_bindings.get(child))):
                raise AnalysisLimit('generator used by an unmodeled expression protocol; analysis is incomplete')
        # Container summaries retain value provenance, not module write
        # authority. Refuse that escape before replacing the mapping with an
        # ordinary vector/heap value and falsely reporting a later call clean.
        if isinstance(node, (ast.Tuple, ast.List, ast.Dict, ast.Set, ast.Starred,
                             ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
            for child in ast.iter_child_nodes(node):
                self.escape_literal_mapping(self.expression_bindings.get(child),
                                            self.expression_references.get(child, NO_REFERENCES), state)
                if 'functools' in _binding_choices(self.expression_bindings.get(child)):
                    self.mutate(frozenset({_PARTIAL_MODULE_REF}), CLEAN, state)
                if any(isinstance(choice, _PartialValue)
                       for choice in _binding_choices(self.expression_bindings.get(child))):
                    raise AnalysisLimit('functools.partial stored in a container; analysis is incomplete')
                if any(isinstance(choice, _GlobalNamespace)
                       for choice in _binding_choices(self.expression_bindings.get(child))):
                    raise AnalysisLimit('globals mapping stored in a container; analysis is incomplete')
        self.expression_facts[node] = fact
        binding = self.expression_bindings.get(node)
        if isinstance(node, ast.Attribute):
            candidates = []
            receiver_refs = self.expression_references.get(node.value, NO_REFERENCES)
            receiver_fact = self.expression_facts.get(node.value, CLEAN)
            bases = _binding_choices(self.expression_bindings.get(node.value))
            if any(isinstance(base, (_DeferredGenerator, _GeneratorNext)) for base in bases):
                if node.attr != '__next__' or not all(isinstance(base, _DeferredGenerator) for base in bases):
                    raise AnalysisLimit('generator attribute protocol is unmodeled; analysis is incomplete')
                binding = _join_bindings(*(_GeneratorNext(
                    base.function, ((_GENERATOR_CURSOR, CLEAN),), ((_GENERATOR_CURSOR, NO_REFERENCES),),
                    ((_GENERATOR_CURSOR, base),)) for base in bases))
                self.expression_bindings[node] = binding
                self.expression_facts[node] = CLEAN
                self.expression_references[node] = NO_REFERENCES
                return CLEAN
            if node.attr == 'communicate':
                # A later global binding may be opaque even though this call
                # received a process earlier. Keep the leaf's identity demand
                # so intervening helpers specialize only the globals they use.
                self.capture_globals.update((self.engine.tree, ref[8:])
                                            for ref in receiver_refs
                                            if isinstance(ref, str) and ref.startswith('@global:'))
            for base in _binding_choices(self.expression_bindings.get(node.value)):
                function = base.function if isinstance(base, (_FunctionValue, _ClosureValue)) else base
                if isinstance(function, ast.FunctionDef) and function in self.engine.generators:
                    raise AnalysisLimit('generator function metadata access is unmodeled; analysis is incomplete')
                if base == _PARTIAL_CHANGED_MODULE:
                    if node.attr == 'partial':
                        candidates.append(_PARTIAL_CHANGED_CONSTRUCTOR)
                        continue
                    base = 'functools'
                if base == 'functools' and node.attr == '__dict__':
                    raise AnalysisLimit('functools module namespace access; analysis is incomplete')
                if isinstance(base, _PartialValue):
                    raise AnalysisLimit('functools.partial attribute access needs binding analysis; '
                                        'analysis is incomplete')
                if isinstance(base, _GlobalNamespace) and base.member is None:
                    candidates.append(_GlobalNamespace(base.module, node.attr))
                    continue
                if isinstance(base, _LiteralMapping) and node.attr == 'get':
                    candidates.append(_BoundCallable(_LITERAL_MAPPING_GET, receiver_refs, receiver_fact, True))
                    continue
                if isinstance(base, ast.ClassDef):
                    members = self.engine.class_members.get(base, {})
                    if self.engine.reads is not None:
                        self.engine.reads[('class_members', base)] = members
                    member = members.get(node.attr)
                    if isinstance(member, _ClassMethodDescriptor):
                        member = _BoundClassMethod(member.function, base, receiver_refs, receiver_fact)
                    candidates.append(member)
                    continue
                if isinstance(base, _ModuleBinding):
                    owner = base.project.modules.get(base.key)
                    if owner is not None:
                        self.capture_globals.add((owner.tree, node.attr))
                    incoming, member, refs = base.project.member(base.key, node.attr, state)
                    fact = join_facts(fact, incoming)
                    self.expression_references[node] = self.expression_references.get(node, NO_REFERENCES) | refs
                    candidates.append(member)
                    continue
                if isinstance(base, _ProcessInput) and node.attr == 'communicate':
                    candidates.append(_BoundCallable('@stdin.' + base.kind, receiver_refs, receiver_fact, True))
                    continue
                name = (_extend_qualifier(base, node.attr) if isinstance(base, str)
                        else _extend_qualifier(base.name, node.attr, receiver_unknown=not base.namespace_proven)
                        if isinstance(base, _BoundCallable)
                        else _opaque_qualifier(_qualified(node, state.bindings), receiver_unknown=True))
                if not name and receiver_refs:
                    # A returned object has identity even without a source
                    # spelling (identity(box).append(...)). Keep the method
                    # and receiver without inventing an import/sanitizer.
                    name = _extend_qualifier('<object>', node.attr)
                framework = name.startswith('@fastapi.router.') or name in _ALL_FRAMEWORK_NAMES
                proven = isinstance(base, str) or isinstance(base, _BoundCallable) and base.namespace_proven
                proven = proven and not any(part in {'<object>', '<unknown>'} for part in name.split('.'))
                candidates.append(_BoundCallable(name, receiver_refs, receiver_fact, proven) if name and receiver_refs and not framework
                                  else name or None)
            binding = _join_bindings(*candidates)
            # A joined module identity can still denote a real source
            # (for example sys.argv), even when no single qualifier wins.
            for candidate in candidates:
                name = candidate.name if isinstance(candidate, _BoundCallable) else candidate
                if isinstance(name, str):
                    fact = join_facts(fact, self.source(node, state, name))
        elif isinstance(node, ast.Lambda):
            binding = self.function_value(node, state)
        elif isinstance(node, ast.NamedExpr):
            binding = self.expression_bindings.get(node.value)
        elif isinstance(node, ast.Starred):
            binding = self.expression_bindings.get(node.value)
        elif isinstance(node, ast.Subscript):
            projected = self.vector_subscript(node, state)
            if projected is not None:
                fact, binding, refs = projected
                self.expression_references[node] = refs
            elif (isinstance(node.value, (ast.Tuple, ast.List))
                  and not any(isinstance(item, ast.Starred) for item in node.value.elts)
                  and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int)
                  and -len(node.value.elts) <= node.slice.value < len(node.value.elts)):
                # Framework annotation tuples use a separate marker binding.
                # Only unexpanded syntax has the same positions as its values.
                binding = self.expression_bindings.get(node.value.elts[node.slice.value])
            mappings = _binding_choices(self.expression_bindings.get(node.value))
            if mappings and all(isinstance(value, _LiteralMapping) for value in mappings):
                contents, unchanged = self.literal_mapping_contents(
                    self.expression_facts.get(node.value, CLEAN),
                    self.expression_references.get(node.value, NO_REFERENCES), state)
                if unchanged and self.literal_mapping_key(node.slice, state):
                    fact, binding = contents, None
                    self.expression_references[node] = NO_REFERENCES
                else:
                    fact = join_facts(fact, contents)
                    self.mutate(self.expression_references.get(node.value, NO_REFERENCES),
                                self.expression_facts.get(node.slice, CLEAN), state)
        elif isinstance(node, ast.Dict):
            if all(isinstance(value, ast.Constant)
                   and type(value.value) in {str, bytes, int, float, complex, bool, type(None)}
                   for value in (*node.keys, *node.values)):
                binding = _LiteralMapping()
        if is_call:
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
            namespace = self.expression_bindings.get(node.value)
            if (not isinstance(namespace, _GlobalNamespace)
                    and any(isinstance(choice, _GlobalNamespace) for choice in _binding_choices(namespace))):
                raise AnalysisLimit('ambiguous globals mapping read; analysis is incomplete')
            if isinstance(namespace, _GlobalNamespace) and namespace.member is None:
                fact, binding, refs, _present = self.read_global(namespace, node.slice, state)
                self.expression_references[node] = refs
            binding = _framework_input(node, state.bindings, evaluated=self.expression_bindings) or binding
        if isinstance(node, (ast.Tuple, ast.List)):
            markers = tuple(self.expression_bindings.get(item) for item in node.elts)
            if any(isinstance(marker, _FrameworkInput) for marker in markers):
                binding = markers
            else:
                binding = self.command_vector(node)
        self.expression_bindings[node] = binding
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
            self.expression_references.setdefault(node, self.expression_references.get(node.value, NO_REFERENCES))
        elif isinstance(node, ast.NamedExpr):
            self.expression_references[node] = self.expression_references.get(node.value, NO_REFERENCES)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Dict, ast.Set, ast.Call)):
            self.expression_references.setdefault(node, frozenset({node}))
        if state.mutated and (self.expression_references.get(node, NO_REFERENCES) & state.mutated):
            self.expression_bindings[node] = _without_object_contract(binding)
        self.expression_facts[node] = fact
        if may_raise and self.exception_states:
            self.possible_exception(state)
        return fact

    def expression(self, node, state):
        if node is None or isinstance(node, ast.Constant):
            return CLEAN
        if isinstance(node, ast.Call):
            return self.call(node, state)
        if isinstance(node, ast.Attribute):
            return join_facts(self.source(node, state), self.expr(node.value, state))
        if isinstance(node, ast.Subscript):
            source = self.source(node, state)
            receiver = self.expr(node.value, state)
            references = self.expression_references.get(node.value, NO_REFERENCES)
            index = self.expr(node.slice, state)
            # Python evaluates the receiver before the index, but performs the
            # lookup afterward. Index evaluation can mutate that same object.
            return join_facts(source, receiver, index,
                              *(state.heap.get(ref, CLEAN) for ref in references))
        if isinstance(node, ast.BinOp):
            return join_facts(self.expr(node.left, state), self.expr(node.right, state))
        if isinstance(node, ast.Set) and self.materialized_generator_depth:
            facts = []
            for child in node.elts:
                facts.append(self.expr(child, state))
                if state.reachable and not self.materialized_generator_hashable(child, state):
                    raise AnalysisLimit('generator materialization set hashing is unresolved; analysis is incomplete')
            return join_facts(*facts)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return join_facts(*(self.expr(child, state) for child in node.elts)) if node.elts else CLEAN
        if isinstance(node, ast.JoinedStr):
            facts = [self.expr(child, state) for child in node.values]
            if (state.reachable and self.generator_consumer_stable(node, set())
                    and self.generator_builtins_stable()
                    and all(self.materialized_generator_string(child, state) for child in node.values)):
                # A single opaque field may return a str subclass; joining
                # multiple fields may release that subclass and run __del__.
                # Only independently proved native fields certify either form.
                self.expression_bindings[node] = _GeneratorString()
            return join_facts(*facts)
        if isinstance(node, ast.FormattedValue):
            value_fact = self.expr(node.value, state)
            primitive = self.formatted_string_operand(node.value, state)
            spec_fact = self.expr(node.format_spec, state)
            if state.reachable and primitive and self.formatted_string_spec(node, state):
                self.expression_bindings[node] = _GeneratorString()
            return join_facts(value_fact, spec_fact)
        if isinstance(node, ast.Dict):
            facts, references = [], {node}
            # Keys and values run in pairs, not as two independent lists.
            # Capture each operand before a later one can rebind its name;
            # nested mutable values remain aliases after construction.
            for key, value in zip(node.keys, node.values):
                for operand in (key, value):
                    facts.append(self.expr(operand, state))
                    immutable = (isinstance(operand, ast.Constant)
                                 or all(isinstance(choice, (_LiteralString, _GeneratorString)) for choice
                                        in _binding_choices(self.expression_bindings.get(operand))))
                    if not immutable:
                        references.update(self.expression_references.get(operand, NO_REFERENCES))
                if (self.materialized_generator_depth and state.reachable
                        and (key is None or not self.materialized_generator_hashable(key, state))):
                    raise AnalysisLimit('generator materialization dictionary hashing is unresolved; '
                                        'analysis is incomplete')
            self.expression_references[node] = frozenset(references)
            return join_facts(*facts, *(state.heap.get(ref, CLEAN) for ref in references))
        if isinstance(node, ast.Starred):
            return self.expr(node.value, state)
        if isinstance(node, ast.Slice):
            return join_facts(
                self.expr(node.lower, state) if node.lower is not None else CLEAN,
                self.expr(node.upper, state) if node.upper is not None else CLEAN,
                self.expr(node.step, state) if node.step is not None else CLEAN,
            )
        if isinstance(node, ast.Compare):
            self.expr(node.left, state)
            self.expr(node.comparators[0], state)
            for comparator in node.comparators[1:]:
                executed = state.copy()
                self.expr(comparator, executed)
                state.replace(_join_states(state, executed))
            return CLEAN  # A comparison produces a bool, not executable text.
        if isinstance(node, ast.UnaryOp):
            operand = self.expr(node.operand, state)
            return CLEAN if isinstance(node.op, ast.Not) else operand
        if isinstance(node, ast.Name):
            return state.value(node.id)
        if isinstance(node, ast.NamedExpr):
            fact = self.expr(node.value, state)
            self.assign(node.target, fact, state, node.value)
            return fact
        if isinstance(node, ast.IfExp):
            left, right = self.condition(node.test, state, inert=bool(self.materialized_generator_depth))
            branches, facts, bindings, references = [], [], [], []
            for expression, branch in ((node.body, left), (node.orelse, right)):
                if branch is None:
                    continue
                fact = self.expr(expression, branch)
                if branch.reachable:
                    branches.append(branch)
                    facts.append(fact)
                    bindings.append(self.expression_bindings.get(expression))
                    references.append(self.expression_references.get(expression, NO_REFERENCES))
            self.expression_bindings[node] = _join_bindings(*bindings)
            self.expression_references[node] = frozenset().union(*references)
            state.replace(_join_states(*branches))
            return join_facts(*facts)
        if isinstance(node, ast.BoolOp):
            facts, bindings, references, exits = [], [], [], []
            continuation = state.copy()
            for index, value in enumerate(node.values):
                if continuation is None:
                    break
                fact = self.expr(value, continuation)
                if not continuation.reachable:
                    break
                if index + 1 == len(node.values):
                    stopped, continuation = continuation, None
                else:
                    truthy, falsy = self.evaluated_truth(
                        value, continuation, inert=bool(self.materialized_generator_depth))
                    stopped, continuation = ((falsy, truthy) if isinstance(node.op, ast.And) else (truthy, falsy))
                if stopped is not None:
                    exits.append(stopped)
                    facts.append(fact)
                    bindings.append(self.expression_bindings.get(value))
                    references.append(self.expression_references.get(value, NO_REFERENCES))
            self.expression_bindings[node] = _join_bindings(*bindings)
            self.expression_references[node] = frozenset().union(*references)
            state.replace(_join_states(*exits))
            return join_facts(*facts)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
            return self.comprehension(node, state)
        if isinstance(node, ast.Await):
            value = self.expr(node.value, state)
            if not state.reachable:
                return CLEAN
            branches, facts, bindings, references = [], [], [], []
            for target in _binding_choices(self.expression_bindings.get(node.value)):
                branch = state.copy()
                if isinstance(target, _DeferredGenerator):
                    raise AnalysisLimit('synchronous generator used as an awaitable; analysis is incomplete')
                if isinstance(target, _DeferredCall):
                    fact = self.invoke(node, branch, _CallTarget(target.function),
                                       _CallInputs([], {}, {}), resumed=target)
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
            if state.cells is not None:
                self.yielded_state = _join_states(self.yielded_state, state)
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
        if isinstance(node, ast.GeneratorExp):
            # The outer iterable executes in the enclosing scope, even when
            # constructing a lazy generator. Inner iterations may be skipped.
            first = node.generators[0]
            consumer = self.generator_exhaustion_consumer(node, state)
            if consumer:
                if any(generator.is_async for generator in node.generators):
                    raise AnalysisLimit('asynchronous generator materialization is unmodeled; analysis is incomplete')
                # Iterator construction can own temporary helper frames too.
                # Check calls before either normal or exceptional completion.
                self.materialized_generator_depth += 1
                try:
                    iterable = self.expr(first.iter, state)
                    return self.comprehension(node, state, iterable=iterable, synchronous_generator=True,
                                              string_result=consumer == 'str.join',
                                              predicate=consumer if consumer in {'any', 'all'} else None)
                finally:
                    self.materialized_generator_depth -= 1
            iterable = self.expr(first.iter, state)
            if not state.reachable:
                return CLEAN
            if any(isinstance(value, (_DeferredGenerator, _GeneratorNext))
                   for value in _binding_choices(self.expression_bindings.get(first.iter))):
                raise AnalysisLimit('generator expression consumes a resumable generator; analysis is incomplete')
            delayed = [node.elt, *(condition for generator in node.generators for condition in generator.ifs),
                       *(generator.iter for generator in node.generators[1:])]
            names, pending = set(), [(expression, self.engine.locals[node]) for expression in delayed]
            while pending:
                expression, bound = pending.pop()
                self.engine.budget.spend()
                if isinstance(expression, ast.Name):
                    if isinstance(expression.ctx, ast.Load) and expression.id not in bound:
                        names.add(expression.id)
                elif isinstance(expression, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                    pending.append((expression.generators[0].iter, bound))
                    inner = bound | self.engine.locals[expression]
                    for index, generator in enumerate(expression.generators):
                        if index:
                            pending.append((generator.iter, inner))
                        pending.extend((condition, inner) for condition in generator.ifs)
                    pending.extend((value, inner) for value in
                                   ((expression.key, expression.value) if isinstance(expression, ast.DictComp)
                                    else (expression.elt,)))
                elif isinstance(expression, ast.Lambda):
                    pending.extend((value, bound) for value in
                                   (*expression.args.defaults, *expression.args.kw_defaults) if value is not None)
                    pending.append((expression.body, bound | self.engine.locals[expression]))
                else:
                    pending.extend((child, bound) for child in ast.iter_child_nodes(expression))
            immediate = self.generator_expression_immediate(node, state)
            for name in names:
                if (name not in self.engine.rebound_globals
                        and name not in self.engine.locals.get(self.scope, ())
                        and name not in self.engine.closures.get(self.scope, ())):
                    continue
                binding = state.bindings.get(name)
                stable_value = (isinstance(binding, (_LiteralString, ast.Constant, _GeneratorString))
                                or self.engine.generator_literal_binding(name))
                stable_import = isinstance(binding, str) and name not in self.engine.rebound_globals
                stable_function = (isinstance(binding, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
                                   and not self.engine.closures.get(binding))
                # Reuse the existing exact-membership/no-escape literal-set
                # proof; a delayed read cannot observe changed contents.
                stable_membership = name in self.engine.url_allowlists
                local = name in self.engine.locals.get(self.scope, ()) and self.scope is not self.engine.tree
                stable = self.engine.generator_stable_binding(name, self.scope, node, immediate=immediate and local)
                if not (stable and (local or stable_value or stable_import or stable_function or stable_membership)):
                    raise AnalysisLimit('generator expression live delayed reads require resume-state analysis; '
                                        'analysis is incomplete')
            nested = state.copy()
            if nested.cells is not None:
                for name in self.engine.locals[node]:
                    nested.cells.names.pop(name, None)
            self.comprehension_environments.append((node, state))
            self.deferred_generator_depth += 1
            try:
                for index, generator in enumerate(node.generators):
                    value = iterable if index == 0 else self.expr(generator.iter, nested)
                    self.assign(generator.target, value, nested)
                    for condition in generator.ifs:
                        self.expr(condition, nested)
                fact = self.expr(node.elt, nested)
            finally:
                self.deferred_generator_depth -= 1
                self.comprehension_environments.pop()
            # Assignment expressions bind in the enclosing scope, while
            # ordinary comprehension targets remain local to the expression.
            for child in ast.walk(node):
                if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
                    name = child.target.id
                    self.write_name(state, name, join_facts(state.get(name, CLEAN), nested.get(name, CLEAN)),
                                    None, state.references.get(name, NO_REFERENCES))
            return fact
        return join_facts(self.source(node, state), *(self.expr(child, state) for child in ast.iter_child_nodes(node)
                                              if isinstance(child, ast.expr)))

    def comprehension(self, node, state, *, iterable=_MISSING, synchronous_generator=False,
                      string_result=False, predicate=None, first_result=False, default=None, borrowed_result=False):
        """Execute eager comprehension clauses in their implicit local scope.

        Heap writes and walrus assignments escape that scope on both normal
        and exceptional edges. Iteration targets do not. Filters are ordered
        branches, and mutable iterables participate in the loop fixed point.
        """
        first = node.generators[0]
        if iterable is _MISSING:
            iterable = self.expr(first.iter, state)
        if any(isinstance(value, (_DeferredGenerator, _GeneratorNext))
               for value in _binding_choices(self.expression_bindings.get(first.iter))):
            raise AnalysisLimit('comprehension consumes a resumable generator; analysis is incomplete')
        if not state.reachable:
            return CLEAN
        original = state.copy()
        local_names = self.engine.locals[node]
        nested = state.copy()
        for name in local_names:
            if nested.cells is not None:
                nested.cells.names.pop(name, None)
            nested[name] = CLEAN
            nested.bindings[name] = None
            nested.references[name] = NO_REFERENCES
        result = CLEAN
        result_bindings, result_references = [], []
        iterator_references = set()
        stopped = []

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
            if projected.cells is not None:
                for name in local_names:
                    ref = original.cells.names.get(name) if original.cells is not None else None
                    if ref is None:
                        projected.cells.names.pop(name, None)
                    else:
                        projected.cells.names[name] = ref
            for name, write in (projected.global_writes or {}).items():
                visible = not self.global_shadowed(name)
                projected.global_writes[name] = _GlobalWrite(write.initial, write.current, visible)
                if visible:
                    projected[name] = write.current.fact
                    projected.bindings[name] = write.current.binding
                    projected.references[name] = write.current.references
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
            if any(isinstance(value, (_DeferredGenerator, _GeneratorNext)) for value in _binding_choices(binding)):
                raise AnalysisLimit('comprehension consumes a resumable generator; analysis is incomplete')
            if synchronous_generator and not self.materialized_generator_iterable(generator.iter, entering):
                raise AnalysisLimit('generator materialization iterator or captured lifetime is unresolved; '
                                    'analysis is incomplete')
            if synchronous_generator:
                iterator_references.update(refs)
            literal = generator.iter
            elements = None
            if (isinstance(literal, (ast.List, ast.Tuple))
                    and not any(isinstance(item, ast.Starred) for item in literal.elts)):
                elements = literal.elts
            elif synchronous_generator and isinstance(literal, ast.Set):
                elements = literal.elts
            elif isinstance(literal, ast.Dict) and all(key is not None for key in literal.keys):
                # Iterating a dictionary yields its keys, not its values.
                # Unknown/duplicate keys cannot establish an exact count.
                elements = literal.keys
            scalar = (literal.value if isinstance(literal, ast.Constant)
                      and isinstance(literal.value, (str, bytes))
                      else binding.value if isinstance(binding, _LiteralString) else None)
            if synchronous_generator and scalar is not None and len(scalar) <= self.comprehension_budget:
                key = (literal, scalar)
                elements = self.engine.generator_literal_elements.get(key)
                if elements is None:
                    elements = tuple(ast.copy_location(ast.Constant(value=value), literal) for value in scalar)
                    self.engine.generator_literal_elements[key] = elements
            empty = (elements == [] or isinstance(literal, ast.Constant)
                     and isinstance(literal.value, (str, bytes)) and not literal.value
                     or scalar is not None and not scalar)
            if empty:
                return entering

            def iteration(current, element=None, captured=None):
                nonlocal result
                if current is None or not current.reachable:
                    return None
                if captured is not None:
                    element_binding, fact, element_refs = captured
                    self.write_name(current, generator.target.id, fact, element_binding, element_refs)
                elif element is not None:
                    element_refs = self.expression_references.get(element, NO_REFERENCES)
                    fact = join_facts(self.expression_facts.get(element, CLEAN),
                                      *(current.heap.get(ref, CLEAN) for ref in element_refs))
                    self.assign(generator.target, fact, current, element)
                    if synchronous_generator and isinstance(generator.target, ast.Name) and isinstance(element, ast.Constant):
                        # Ordinary numeric constants have no callable binding;
                        # their exact primitive identity is still lifetime evidence.
                        current.bindings[generator.target.id] = element
                else:
                    fact = join_facts(value, *(current.heap.get(ref, CLEAN) for ref in refs))
                    self.assign(generator.target, fact, current)
                    if isinstance(generator.target, ast.Name):
                        if elements is not None:
                            current.bindings[generator.target.id] = _join_bindings(*(
                                item if synchronous_generator and isinstance(item, ast.Constant)
                                else self.expression_bindings.get(item) for item in elements))
                            current.references[generator.target.id] = frozenset().union(*(
                                self.expression_references.get(item, NO_REFERENCES) for item in elements))
                        elif synchronous_generator and isinstance(binding, (_LiteralString, _GeneratorString)):
                            current.bindings[generator.target.id] = _GeneratorString(format_safe=binding.format_safe)
                        elif generator.iter in self.generator_returns:
                            current.bindings[generator.target.id] = binding
                            current.references[generator.target.id] = refs
                for name in local_names:
                    if current.references.get(name, NO_REFERENCES) & current.mutated:
                        current.bindings[name] = _without_object_contract(current.bindings.get(name))
                    if current.cells is not None and name in current.cells.names:
                        self.write_name(current, name, current.get(name, CLEAN), current.bindings.get(name),
                                        current.references.get(name, NO_REFERENCES))
                skipped = []
                for condition in generator.ifs:
                    current, rejected = self.condition(condition, current)
                    if (synchronous_generator and (current is not None or rejected is not None)
                            and not self.materialized_generator_inert(
                            condition, current if current is not None else rejected if rejected is not None else entering)):
                        raise AnalysisLimit('generator materialization filter protocol is unresolved; '
                                            'analysis is incomplete')
                    skipped.append(rejected)
                if current is not None:
                    if index + 1 < len(node.generators):
                        current = clause(index + 1, current)
                    elif predicate:
                        truthy, falsy = self.condition(node.elt, current, inert=True)
                        finished, current = ((truthy, falsy) if predicate == 'any' else (falsy, truthy))
                        if finished is not None:
                            stopped.append(finished)
                    else:
                        values = ((node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,))
                        if borrowed_result:
                            self.materialized_generator_depth -= 1
                        try:
                            fact = join_facts(*(self.expr(item, current) for item in values))
                        finally:
                            if borrowed_result:
                                self.materialized_generator_depth += 1
                        if current.reachable:
                            if string_result and not self.materialized_generator_string(node.elt, current):
                                raise AnalysisLimit('string join generator element is not a proven builtin string; '
                                                    'analysis is incomplete')
                            if (synchronous_generator and not borrowed_result
                                    and not self.materialized_generator_inert(node.elt, current)):
                                raise AnalysisLimit('generator materialization result lifetime is unresolved; '
                                                    'analysis is incomplete')
                            result = join_facts(result, fact)
                            if first_result:
                                result_bindings.append(self.expression_bindings.get(node.elt))
                                result_references.append(self.expression_references.get(node.elt, NO_REFERENCES))
                                stopped.append(current)
                                current = None
                if synchronous_generator and current is not None and current.mutated & iterator_references:
                    raise AnalysisLimit('generator materialization mutates its captured iterator; '
                                        'analysis is incomplete')
                return _join_states(current, *skipped)

            # Fresh sequence literals cannot acquire additional elements from
            # the body. Preserve evaluation order and element/callable aliases
            # without inventing a second iteration of a singleton sequence.
            if (elements is not None and (isinstance(literal, (ast.List, ast.Tuple)) or scalar is not None)
                    and len(elements) <= self.comprehension_budget):
                self.comprehension_budget -= len(elements)
                current = entering
                for element in elements:
                    current = iteration(current, element)
                return current
            if (synchronous_generator and isinstance(binding, _ArgumentVector)
                    and isinstance(generator.target, ast.Name)
                    and len(binding.operands) <= self.comprehension_budget):
                self.comprehension_budget -= len(binding.operands)
                current = entering
                for position, (element_binding, fact) in enumerate(binding.operands):
                    current = iteration(current, captured=(element_binding, fact, binding.references_at(position)))
                return current
            if elements is not None:
                value = join_facts(*(self.expression_facts.get(item, CLEAN) for item in elements))
            head = entering.copy()
            exits = None if elements or scalar else entering.copy()
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
        if predicate:
            choices = []
            if normal is not None:
                choices.append(_PREDICATE_RESULTS[predicate == 'all'])
            if stopped:
                choices.append(_PREDICATE_RESULTS[predicate == 'any'])
            self.expression_bindings[node] = _join_bindings(*choices)
            normal = _join_states(normal, *stopped)
        if first_result:
            # Explicit StopIteration raised inside a generator is converted
            # to RuntimeError. Natural exhaustion below remains a separate
            # edge, and a supplied default handles only that edge.
            outgoing = [_Completion(item.kind, item.state, item.value, item.references,
                                    '@exception:RuntimeError', 'RuntimeError')
                        if item.kind == 'raise' and item.exception_type == 'StopIteration' else item
                        for item in outgoing]
            if normal is not None:
                if default is None:
                    outgoing.append(_Completion('raise', normal, exception_type='StopIteration'))
                else:
                    result = join_facts(result, self.expression_facts.get(default, CLEAN))
                    result_bindings.append(self.expression_bindings.get(default))
                    result_references.append(self.expression_references.get(default, NO_REFERENCES))
                    stopped.append(normal)
            normal = _join_states(*stopped)
            self.expression_bindings[node] = _join_bindings(*result_bindings)
        if synchronous_generator and any(
                current is not None and current.mutated & iterator_references
                for current in (normal, exceptional, *(item.state for item in outgoing))):
            raise AnalysisLimit('generator materialization mutates its captured iterator; '
                                'analysis is incomplete')
        self.pending.extend(_Completion(item.kind, project(item.state), item.value,
                                        item.references, item.binding, item.exception_type)
                            for item in _merge_completions(outgoing))
        if exceptional is not None:
            self.exception_states[-1] = _join_states(self.exception_states[-1], project(exceptional))
        state.replace(project(normal))
        self.expression_references[node] = (frozenset().union(*result_references)
                                            if first_result else frozenset({node}))
        return result

    def block(self, statements, state):
        track_last = isinstance(self.scope, ast.Module)
        for node in statements:
            if state is None or not state.reachable:
                break
            if track_last:
                self.last_state = state.copy()
            state = self.statement(node, state)
            if track_last and state is not None:
                self.last_state = state.copy()
        return state if state is not None and state.reachable else None

    def statement(self, node, state):
        self.engine.budget.spend()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Decorator expressions run before defaults. Preserve the real
            # router identity even if a later default rebinds its name.
            route = False
            native_route_decorators = True
            route_dependencies = []
            descriptors = []
            for decorator in node.decorator_list:
                is_route = isinstance(decorator, ast.Call) and _imported_name(decorator.func, state.bindings) in {
                    f'@fastapi.router.{method}' for method in _ROUTE_METHODS}
                route = route or is_route
                native_route_decorators = native_route_decorators and is_route
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
            self.engine.describe_framework(node, default_inputs, state.bindings, route, route_dependencies,
                                           native_builtins=(self.generator_builtins_stable()
                                                            and native_route_decorators))
            descriptor = ('class' if descriptors in (['classmethod'], ['builtins.classmethod'])
                          else not descriptors or descriptors in (['staticmethod'], ['builtins.staticmethod']))
            self.engine.define('class_callables', node, descriptor)
            self.write_name(state, node.name, CLEAN, self.function_value(node, state))
        elif isinstance(node, ast.ClassDef):
            for expression in (*node.bases, *node.decorator_list):
                self.expr(expression, state)
            for keyword in node.keywords:
                self.expr(keyword.value, state)
            namespace = state.copy()
            if namespace.cells is not None:
                for name in _local_names(node):
                    namespace.cells.names.pop(name, None)
            self.class_environments.append((node, state))
            try:
                completed = self.block(node.body, namespace)
            finally:
                self.class_environments.pop()
            if completed is None:
                return None
            for ref, fact in completed.heap.items():
                state.heap[ref] = join_facts(state.heap.get(ref, CLEAN), fact)
            if completed.cells is not None:
                cells = state.cell_state()
                cells.multiple.update(completed.cells.multiple)
                for ref, contents in completed.cells.contents.items():
                    state.put_cell(ref, contents, written=ref in completed.cells.written)
            for name, write in (completed.global_writes or {}).items():
                self.put_global(name, write.current, state)
            members = {}
            if self.engine.plain_class(node, state):
                for name in _local_names(node):
                    value = completed.bindings.get(name)
                    function = value.function if isinstance(value, (_ClosureValue, _FunctionValue)) else value
                    if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        descriptor = self.engine.class_callables.get(function)
                        if self.engine.reads is not None:
                            self.engine.reads[('class_callables', function)] = descriptor
                        value = (_ClassMethodDescriptor(value) if descriptor == 'class'
                                 else value if descriptor else None)
                    members[name] = value
            self.engine.define('class_members', node, members)
            self.write_name(state, node.name, CLEAN, node, frozenset({node}))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or alias.name.split('.')[0]
                imported = (self.engine.project.imported(self.engine, node, alias, state)
                            if self.engine.project is not None else None)
                if imported is not None:
                    fact, binding, refs = imported
                    self.write_name(state, local, fact, binding, refs)
                    continue
                binding = (f'{node.module}.{alias.name}' if isinstance(node, ast.ImportFrom)
                           else alias.name if alias.asname else local)
                refs = frozenset({_PARTIAL_MODULE_REF}) if binding == 'functools' else NO_REFERENCES
                if binding == 'functools.partial' and _PARTIAL_MODULE_REF in state.mutated:
                    binding = _PARTIAL_CHANGED_CONSTRUCTOR
                self.write_name(state, local, CLEAN, binding, refs)
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
                self.write_name(state, node.target.id, state.get(node.target.id, CLEAN),
                                state.bindings.get(node.target.id), references)
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
                self.observed_raises.append((value, self.expression_references.get(node.msg, NO_REFERENCES)))
                self.pending.append(_Completion('raise', failed, value, exception_type='AssertionError'))
            if isinstance(node.test, ast.Constant) and not node.test.value:
                return None
        elif isinstance(node, ast.Expr):
            self.expr(node.value, state)
        elif isinstance(node, ast.Return):
            value = self.expr(node.value, state)
            if not state.reachable:
                return None
            self.observed_returns.append((value, self.expression_references.get(node.value, NO_REFERENCES)))
            self.observed_return_bindings.append(self.expression_bindings.get(node.value))
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
                self.observed_raises.append((previous.value, previous.references))
                self.pending.append(_Completion('raise', state.copy(), previous.value,
                                                previous.references, previous.binding, previous.exception_type))
            else:
                self.observed_raises.append((value, self.expression_references.get(node.exc, NO_REFERENCES)))
                self.pending.append(_Completion('raise', state.copy(), value,
                                                self.expression_references.get(node.exc, NO_REFERENCES),
                                                self.expression_bindings.get(node.exc), exception_type))
            return None
        elif isinstance(node, ast.If):
            self.expr(node.test, state)
            yes, no = state.copy(), state.copy()
            self.refine_url_guard(node.test, yes, True)
            self.refine_url_guard(node.test, no, False)
            return _join_states(self.block(node.body, yes), self.block(node.orelse, no))
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
                    self.write_name(state, target.id, CLEAN, None, bound=False)
                elif isinstance(target, (ast.Subscript, ast.Attribute)):
                    self.assign(target, CLEAN, state, deleting=True)
        elif isinstance(node, ast.Global) and self.class_environments:
            raise AnalysisLimit('class-body global declaration; analysis is incomplete')
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
            generators = _binding_choices(binding)
            if any(isinstance(value, (_DeferredGenerator, _GeneratorNext)) for value in generators):
                return self.generator_loop(node, state, generators)
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
                    self.write_name(body, node.target.id, body.get(node.target.id, CLEAN), binding, references)
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
        exceptions = []
        for item in _merge_completions(item for item in self.pending if item.kind == 'raise'):
            global_writes = self.export_globals(item.state)
            exceptions.append(ExceptionSummary(
                item.exception_type,
                join_facts(item.value, *(item.state.heap.get(ref, CLEAN) for ref in item.references)),
                mutations_on(item.state),
                self.export_cells(item.state, tuple(contents.binding for _module, _name, contents in global_writes)),
                frozenset(item.state.cells.multiple) if item.state.cells is not None else frozenset(),
                global_writes))
        if self.normal_state is not None and not isinstance(self.scope, ast.Lambda):
            returned_bindings.append(None)  # Implicit `return None`.
        returned_binding = _join_bindings(*returned_bindings)
        yielded_binding = _join_bindings(*self.yielded_bindings)
        if normal is not None:
            returned_binding = self.refresh_function_defaults(returned_binding, normal.heap, normal.mutated)
        yielded_binding = self.refresh_function_defaults(yielded_binding, self.mutations, self.mutations.keys())
        # finally may change an object after its return expression was read.
        # The object still returns, but its previous argv/process shape does
        # not. Keep this independent from whether the write added any taint.
        if returned_references & self.mutations.keys():
            returned_binding = _without_object_contract(returned_binding)
        if self.yielded_references & self.mutations.keys():
            yielded_binding = _without_object_contract(yielded_binding)
        cell_state = _join_states(normal, self.yielded_state) if self.yielded_state is not None else normal
        global_writes = self.export_globals(cell_state)
        cells = self.export_cells(cell_state, (returned_binding, yielded_binding,
                                  *(contents.binding for _module, _name, contents in global_writes)))
        return FunctionSummary(
            returned=returned, effects=tuple((*key, fact) for key, fact in sorted(self.effects.items())),
            yielded=yielded, mutations=mutations,
            returned_references=frozenset(ref for ref in returned_references if isinstance(ref, str)),
            yielded_references=frozenset(ref for ref in self.yielded_references if isinstance(ref, str)),
            returned_binding=returned_binding,
            yielded_binding=yielded_binding,
            can_return=normal is not None,
            exceptions=tuple(exceptions),
            capture_globals=frozenset(self.capture_globals),
            value_parameters=frozenset(self.value_parameters),
            cells=cells,
            multiple_cells=frozenset(cell_state.cells.multiple)
            if cell_state is not None and cell_state.cells is not None else frozenset(),
            global_writes=global_writes,
        )


class _Analysis:
    flow_class = _Flow

    def __init__(self, tree, project=None):
        self.tree = tree
        self.project = project
        # Import-cycle fallback can disable the resolver without disabling
        # rollback of incomplete writes to shared definition/summary tables.
        self.journal = project.journal if project is not None else None
        self.function_owners = {}
        self.globals = _State()
        # Mapping membership distinguishes only globals actually read through
        # a namespace mapping; ordinary global reads keep compact summaries.
        self.namespace_read_names = set()
        self.summaries = {}
        self.defaults = {}
        self.framework_inputs = {}
        self.framework_values = {}
        self.framework_dependencies = {}
        # While a job is solved: every summary and definition-time table
        # entry it reads, so an unchanged job is not solved again.
        self.reads = None
        self.writes = None
        self.local_journal = None
        self.failed_scopes = {}
        self.failed_scope_diagnostics = {}
        self.failed_summaries = {}
        self.partial_scope_effects = {}
        self.observed_effects = {}
        self.escaping_callables = {}
        self.scope_errors = []
        self.scope_diagnostics = []
        self.scope_remaining = {}
        self.scope_limits = {}
        self.line_offset = 0
        self.source_path = None
        self.default_references = {}
        self.default_bindings = {}
        self.class_members = {}
        self.class_callables = {}
        # The syntax tree is immutable during analysis. Build its structural
        # tables from one breadth-first walk; scope bodies likewise need only
        # one walk for local names and generator classification. Rewalking all
        # selected source here adds substantial setup cost before any flow is
        # analyzed, without providing new information.
        nodes = tuple(ast.walk(tree))
        self.parents = {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)}
        self.generator_readonly_builtins = _readonly_builtin_modules(nodes, self.parents)
        literal_authority, literal_authority_limited = _literal_execution_authority(nodes)
        self.framework_annotation_metadata = any(
            isinstance(node, ast.Attribute) and node.attr in {
                '__annotations__', '__signature__', '__wrapped__', '__annotate__'} for node in nodes)
        # Builtin functions expose their owning module through __self__.
        # Reflective aliases revoke native identity proofs even when no
        # import or direct attribute store names the builtins module.
        reflection = {'getattr', 'hasattr', 'setattr', 'delattr', 'vars', 'attrgetter', 'methodcaller',
                      'getattr_static'}
        reflection_flags = tuple(any(
            isinstance(node, ast.Name) and node.id in reflection
            or isinstance(node, ast.Attribute) and node.attr in reflection | {
                '__self__', '__func__', '__closure__', '__dict__', '__class__', '__subclasses__',
                '__getattr__', '__getattribute__', '__setattr__', '__delattr__'}
            or isinstance(node, ast.ImportFrom) and node.module in {'builtins', 'operator', 'inspect'}
            and any(alias.name in reflection for alias in node.names)
            for node in group) for group in (nodes, literal_authority))
        self.generator_builtin_reflection = reflection_flags[0]
        self.generator_literal_authority_exposed = literal_authority_limited or reflection_flags[1]
        # Primitive input-result proofs must not outlive an exposed/replaced
        # builtins namespace. Projects combine this property across modules.
        self.generator_input_identity = not self.generator_builtin_reflection and not any(
            isinstance(node, ast.ImportFrom) and any(alias.name == '*' for alias in node.names)
            or isinstance(node, ast.Name) and node.id in {'builtins', '__builtins__', '__import__',
                                                     'sys', 'importlib', 'import_module'}
            and node.id not in self.generator_readonly_builtins
            or isinstance(node, ast.Import) and any(alias.name.split('.')[0] in {
                'builtins', 'sys', 'importlib'} and not (
                    alias.name == 'builtins' and (alias.asname or alias.name) in self.generator_readonly_builtins)
                for alias in node.names)
            or isinstance(node, ast.ImportFrom) and node.module
            and (node.module.split('.')[0] in {'sys', 'importlib'}
                 or node.module == 'builtins' and any(alias.name not in {
                     'input', 'list', 'tuple', 'any', 'all', 'next'} for alias in node.names))
            or isinstance(node, ast.Attribute) and node.attr in {
                '__builtins__', '__globals__', 'f_builtins', 'f_globals', 'stdin', 'import_module'}
            or isinstance(node, ast.Constant) and isinstance(node.value, str)
            and node.value in {'builtins', '__builtins__', '__globals__', 'f_builtins', 'f_globals',
                               'stdin', 'sys', 'importlib', 'import_module'}
            for node in nodes)
        # An exhausted analysis is an explicit failure, never a clean result.
        # Scale with syntax size, while charging transfers and fact expansion
        # rather than only the number of outer fixed-point iterations.
        self.work_limit = _work_setting('UBS_PYTHON_FLOW_MAX_STEPS',
                                       min(10_000_000, max(500_000, 128 * len(nodes))))
        scope_override = _work_setting('UBS_PYTHON_FLOW_SCOPE_STEPS', None)
        self.budget = Budget(self.work_limit)
        # A literal allow-list is a proof only if every other use is exact
        # membership testing. Rebinding, mutation, aliasing or passing the set
        # to an opaque call invalidates it throughout this conservative model.
        self.url_allowlists = set()
        allowlist_targets = []
        for statement in tree.body:
            if not (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                    and isinstance(statement.targets[0], ast.Name)
                    and isinstance(statement.value, (ast.Set, ast.Tuple, ast.List))
                    and statement.value.elts and all(isinstance(item, ast.Constant)
                        and isinstance(item.value, str) and item.value
                        for item in statement.value.elts)):
                continue
            allowlist_targets.append(statement.targets[0])
        if allowlist_targets:
            # Large analyzers define many constant sets. Index the immutable
            # syntax once rather than rescanning every node for every set;
            # all invalidating scopes and dynamic namespace writes still count.
            uses_by_name = {target.id: [] for target in allowlist_targets}
            rebound_names = set()
            dynamic_namespace = False
            for node in nodes:
                if isinstance(node, ast.Name):
                    if node.id in uses_by_name:
                        uses_by_name[node.id].append(node)
                elif isinstance(node, ast.arg):
                    rebound_names.add(node.arg)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                       ast.ExceptHandler)):
                    rebound_names.add(node.name)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        if alias.name == '*':
                            dynamic_namespace = True
                        rebound_names.add(alias.asname or alias.name.split('.')[0])
                elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                      and node.func.id in {'exec', 'eval', 'globals', 'locals', 'vars'}):
                    dynamic_namespace = True
                elif (capture := _pattern_capture(node)) is not None:
                    rebound_names.add(capture)
            for target in allowlist_targets:
                if dynamic_namespace or target.id in rebound_names:
                    continue
                uses = [node for node in uses_by_name[target.id] if node is not target]
                if uses and all(isinstance(node.ctx, ast.Load)
                    and isinstance(self.parents.get(node), ast.Compare)
                    and len(self.parents[node].ops) == 1
                    and isinstance(self.parents[node].ops[0], ast.In)
                    and self.parents[node].comparators == [node] for node in uses):
                    self.url_allowlists.add(target.id)
        self.call_sites = {node: _expanded_call(node) for node in nodes if isinstance(node, ast.Call)}
        self.original_calls = {view: node for node, view in self.call_sites.items()}
        self.imports = tuple(node for node in nodes if isinstance(node, (ast.Import, ast.ImportFrom)))
        self.method_calls = {}
        self.partial_calls = {}
        self.functions = [node for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))]
        self.generators = set()
        self.generator_peers = (self,)
        self.generator_helper_proofs = {}
        self.generator_receiver_proofs = {}
        self.generator_literal_elements = {}
        self.definition_writers = set()
        self.direct_global_functions = set()
        self.locals = {}
        self.generator_binders = {}
        self.generator_external_writers = {name for node in nodes if isinstance(node, (ast.Global, ast.Nonlocal))
                                          for name in node.names}
        namespace_flags = tuple(any(
            isinstance(node, ast.Name) and node.id in {'globals', 'locals', '__builtins__', '__import__'}
            or isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == 'vars' and not node.args and not node.keywords
            or isinstance(node, ast.Attribute) and node.attr in {
                '__globals__', '__builtins__', 'f_globals', 'f_locals', '__dict__', 'modules',
                'globals', 'locals', 'vars', 'import_module'}
            or isinstance(node, ast.Name) and node.id in {'setattr', 'delattr'}
            or isinstance(node, ast.ImportFrom)
            and (any(alias.name == '*' for alias in node.names)
                 or node.module == 'importlib' and any(alias.name in {'import_module', 'reload'} for alias in node.names)
                 or node.module == 'sys' and any(alias.name == 'modules' for alias in node.names)
                 or node.module == 'builtins' and any(alias.name in {
                     'globals', 'locals', 'vars', '__import__'} for alias in node.names))
            for node in group) for group in (nodes, literal_authority))
        self.generator_namespace_exposed = namespace_flags[0]
        literal_comprehension_targets = {part for node in literal_authority
                                        if isinstance(node, ast.comprehension)
                                        for part in ast.walk(node.target)}
        self.generator_literal_authority_exposed |= namespace_flags[1] or any(
            isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del))
            or isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
            and node not in literal_comprehension_targets
            or isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            or isinstance(node, ast.ExceptHandler) and node.name is not None
            or _pattern_capture(node) is not None
            for node in literal_authority)
        self.generator_attribute_writes = {node.attr for node in nodes if isinstance(node, ast.Attribute)
                                           and isinstance(node.ctx, (ast.Store, ast.Del))}
        frame_capabilities, literal_frames = (tuple(
            node for node in group if
            isinstance(node, ast.Name) and node.id in {'locals', '_getframe', 'currentframe', '_current_frames'}
            or isinstance(node, ast.Attribute) and node.attr in {
                'f_locals', '_getframe', 'currentframe', '_current_frames'}
            or isinstance(node, ast.ImportFrom) and node.module in {'sys', 'inspect'}
            and any(alias.name in {'_getframe', 'currentframe', '_current_frames'} for alias in node.names)
            or isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == 'vars' and not node.args and not node.keywords)
            for group in (nodes, literal_authority))
        self.generator_literal_authority_exposed |= bool(literal_frames)
        self.generator_execution_capabilities = tuple(node for node in nodes
            if isinstance(node, ast.Name) and node.id in {'eval', 'exec'}
            or isinstance(node, ast.Attribute) and node.attr in {'eval', 'exec'})
        raw_used = {}
        self.declared_globals = {}
        for scope in [tree, *self.functions]:
            body = tuple(_scope_nodes(scope))
            self.locals[scope] = _local_names(scope, body)
            # Count binding sites in their lexical owner, including eager
            # child headers. A same-spelled local in another function is not
            # a write to this frame. Comprehension targets have their own scope.
            binding_nodes = list(body)
            for child in body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    headers = [*getattr(child, 'decorator_list', ()), *child.args.defaults,
                               *(value for value in child.args.kw_defaults if value is not None)]
                    binding_nodes.extend(part for header in headers for part in ast.walk(header))
            targets = {part for child in binding_nodes
                       if isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
                       for generator in child.generators for part in ast.walk(generator.target)}
            binders = defaultdict(list)
            for child in binding_nodes:
                names = ([child.id] if isinstance(child, ast.Name)
                         and isinstance(child.ctx, (ast.Store, ast.Del)) and child not in targets
                         else [child.name] if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                                 ast.ClassDef, ast.ExceptHandler))
                         else [alias.asname or alias.name.split('.')[0] for alias in child.names]
                         if isinstance(child, (ast.Import, ast.ImportFrom))
                         else [_pattern_capture(child)] if _pattern_capture(child) is not None else [])
                for name in names:
                    if name is not None:
                        binders[name].append(child)
            if scope is not tree:
                for argument in (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs,
                                 *(arg for arg in (scope.args.vararg, scope.args.kwarg) if arg is not None)):
                    binders[argument.arg].append(argument)
            self.generator_binders[scope] = dict(binders)
            self.declared_globals[scope] = {name for node in body if isinstance(node, ast.Global)
                                             for name in node.names}
            if scope is not tree:
                limit = (scope_override if scope_override is not None else
                         min(250_000, max(20_000, 64 * len(body), 8 * len(nodes))))
                self.scope_limits[scope] = limit
                self.scope_remaining[scope] = limit
                if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda))
                       for node in body):
                    self.definition_writers.add(scope)
                raw_used[scope] = _used_names(scope, body)
                if _direct_global_reads_only(scope):
                    self.direct_global_functions.add(scope)
                if any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in body):
                    self.generators.add(scope)
        for node in nodes:
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                self.locals[node] = {child.id for generator in node.generators
                                     for child in ast.walk(generator.target)
                                     if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)}
        self.generator_frame_exposed = any(not self.generator_readonly_frame(node) for node in frame_capabilities)
        self.generator_namespace_exposed |= self.generator_frame_exposed
        self.global_names = self.locals[tree]
        self.rebound_globals = {node.id for node in nodes
                                if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
                                and node.id in self.global_names}
        # A literal mapping key can replace a declaration without a Name
        # store. Index possible keys before solving helpers, so cached raw
        # function identities never predate a later namespace replacement.
        for node in nodes:
            keys = ()
            if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
                keys = (node.slice,)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'update':
                self.rebound_globals.update(keyword.arg for keyword in node.keywords
                                            if keyword.arg in self.global_names)
                keys = (key for arg in node.args if isinstance(arg, ast.Dict) for key in arg.keys)
            self.rebound_globals.update(key.value for key in keys
                                        if isinstance(key, ast.Constant) and isinstance(key.value, str)
                                        and key.value in self.global_names)
        # Formal globals are lexical constants, not concrete heap facts.
        # Reusing their immutable traces preserves paths and lets state joins
        # recognize unchanged globals by identity across fixed-point passes.
        self.global_symbols = {
            name: (frozenset({TaintTrace(name, parameter=f'@global:{name}', path=(name,))}),
                   frozenset({f'@global:{name}'}), _SymbolicValue(f'@global:{name}'))
            for name in self.global_names
        }
        self.cell_owners = {function: {} for function in self.functions}
        self.cell_locals = {}
        for function in self.functions:
            for name in raw_used[function] - self.locals[function] - self.declared_globals[function]:
                parent = self.enclosing(function)
                intermediates = []
                while parent is not None and not isinstance(parent, ast.Module):
                    if isinstance(parent, ast.ClassDef):
                        parent = self.enclosing(parent)
                        continue  # A method does not close over the class namespace.
                    if name in self.declared_globals.get(parent, ()):
                        break  # An intervening global declaration is a lexical barrier.
                    if name in self.locals.get(parent, ()):
                        self.cell_owners[function][name] = parent
                        self.cell_locals.setdefault(parent, set()).add(name)
                        for intermediate in intermediates:
                            self.cell_owners[intermediate][name] = parent
                        break
                    if parent in self.cell_owners:
                        intermediates.append(parent)
                    parent = self.enclosing(parent)
        for function in reversed(self.functions):
            parent = self.enclosing(function)
            while parent is not None and not isinstance(parent, ast.Module):
                if parent in raw_used:
                    raw_used[parent].update(raw_used[function])
                parent = self.enclosing(parent)
        self.closures = {function: set(owners) for function, owners in self.cell_owners.items()}
        # A cutoff can precede the invocation of an escaped closure. Keep the
        # old conservative may-alias candidates once for incomplete recovery,
        # rather than duplicating them in every completed function's state.
        # This stays module-local when project structural tables are shared.
        self.closure_names = frozenset().union(*self.closures.values())
        self.used_names = {
            # Child reads have already propagated to their lexical parents.
            # A function also needs the cells available in its own enclosing
            # scopes, including sibling helpers that it can call indirectly.
            # Captures in an unrelated lexical tree are not dependencies:
            # adding their module-wide union here retained O(functions^2)
            # names before the first bounded transfer could run.
            function: (raw_used[function] | self.locals[function] | self.closures[function])
            for function in self.functions
        }
        self.shadowed_globals = {
            function: (self.locals[function] | self.closures[function]) & self.global_names
            for function in self.functions
        }
        self.shadowed_global_values = {
            function: {f'@global:{name}': self.global_symbols[name][2] for name in shadowed}
            for function, shadowed in self.shadowed_globals.items()
        }
        self.active_globals = {
            function: tuple(
                name for name in (self.used_names[function] & self.global_names)
                if name not in self.shadowed_globals[function]
            )
            for function in self.functions
        }
        self.base_global_bound = {
            f'@global:{name}': self.global_symbols[name][0]
            for name in self.global_names
        }
        self.base_global_refs = {
            f'@global:{name}': self.global_symbols[name][1]
            for name in self.global_names
        }
        self.refresh_globals(self.globals, ready=False)

    def refresh_globals(self, globals_, *, ready=True):
        # Framework entries are solved without an ordinary Python call site.
        # Publish the effective mapping contracts after initialization, not a
        # literal initializer whose object has since been mutated or escaped.
        for name, binding in globals_.bindings.items():
            for value in _binding_choices(binding):
                references = (globals_.references.get(name, NO_REFERENCES) if isinstance(value, _LiteralMapping)
                              else value.references if isinstance(value, _BoundCallable)
                              and value.name == _LITERAL_MAPPING_GET else NO_REFERENCES)
                if references & globals_.mutated:
                    globals_.bindings[name] = _without_object_contract(binding)
                    break
        self.globals = globals_
        self.namespace_ready = ready
        aliases = {}
        for name, references in globals_.references.items():
            if name not in self.global_symbols:
                continue
            self.budget.spend(len(references))
            for ref in references:
                if isinstance(ref, ast.AST):
                    aliases.setdefault(ref, set()).add('@global:' + name)
        self.global_object_aliases = {ref: frozenset(names) for ref, names in aliases.items()}
        bindings = globals_.bindings
        self.base_global_values = {
            f'@global:{name}': bindings.get(name)
            for name in self.global_names
        }
        self.base_global_values.update(
            ('@presence:' + name, _namespace_presence(globals_, name)) for name in self.global_names)
        self.has_base_bound_methods = any(
            isinstance(choice, _BoundClassMethod)
            for val in self.base_global_values.values()
            if val is not None
            for choice in _binding_choices(val)
        )
        self.class_globals = tuple(
            f'@global:{name}'
            for name in self.global_names
            if isinstance(bindings.get(name), (frozenset, ast.ClassDef, _BoundClassMethod))
            and any(isinstance(v, (ast.ClassDef, _BoundClassMethod))
                    for v in _binding_choices(bindings.get(name)))
        )

    def owner(self, function):
        # An opaque import cycle disables the project resolver, not lexical
        # ownership. Shared callback jobs must still use their defining
        # module; otherwise every later cycle re-solves foreign functions
        # against its own globals and overwrites their summaries.
        return self.function_owners.get(function, self)

    @staticmethod
    def plain_class(node, state):
        """Prove the bounded class namespace used for class-qualified calls.

        There is no instance, arbitrary-descriptor or inheritance simulation. Only
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

    def generator_stable_binding(self, name, scope, creation=None, *, immediate=False):
        """Prove a delayed read cannot observe a later lexical rebinding."""
        if name in self.generator_external_writers:
            return False
        if name in self.closures.get(scope, ()):
            return False  # A different live frame needs its own resume state.
        owner = scope if name in self.locals.get(scope, ()) else self.tree
        binders = self.generator_binders.get(owner, {}).get(name, ())
        if not binders:
            return False
        if owner is self.tree:
            if self.generator_namespace_exposed or len(binders) != 1 or creation is None:
                return False
            engines = ((engine for _path, _text, engine, _offset in self.project.sources)
                       if self.project is not None else (self,))
            # A namespace capability in an unrelated selected file is not
            # evidence that this module's binding can change. Keep actual
            # attribute replacements and importers that can address this
            # owner's namespace; builtin/stdin lifetime proof is separate.
            if any(name in engine.generator_attribute_writes
                   or engine is not self and engine.generator_namespace_exposed
                   and self in self.project.import_dependencies.get(engine, ())
                   for engine in engines):
                return False
            binder = binders[0]
            statement = binder if isinstance(binder, ast.stmt) else self.parents.get(binder)
            # A single top-level initialization is stable; a conditional or
            # repeated binding is not certified by mere source ordering.
            if (statement not in self.tree.body or isinstance(binder, ast.Name)
                    and (not isinstance(statement, (ast.Assign, ast.AnnAssign))
                         or not isinstance(binder.ctx, ast.Store))):
                return False
            # The original AST owns the execution position; normalized call
            # views are not independent allocation/initialization evidence.
            original = self.original_calls.get(creation, creation)
            if original not in self.parents:
                return False
            return ((statement.end_lineno, statement.end_col_offset)
                    < (original.lineno, original.col_offset))
        if owner is not scope or creation is None or self.generator_frame_exposed:
            return False
        consumer = self.parents.get(creation) if immediate else None
        position = ((consumer.end_lineno, consumer.end_col_offset)
                    if consumer is not None else (creation.lineno, creation.col_offset))
        if any(isinstance(binder, ast.Name) and isinstance(binder.ctx, ast.Del)
               or isinstance(binder, ast.ExceptHandler) for binder in binders):
            return False
        if any(not isinstance(binder, ast.arg)
               and ((creation.lineno, creation.col_offset) <= (binder.lineno, binder.col_offset) < position
                    if immediate else (binder.lineno, binder.col_offset) >= position)
               for binder in binders):
            return False
        def binding_statement(binder):
            if isinstance(binder, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return binder
            parent = self.parents.get(binder)
            while isinstance(parent, (ast.Tuple, ast.List, ast.Starred)) and isinstance(parent.ctx, ast.Store):
                binder, parent = parent, self.parents.get(parent)
            return parent if isinstance(parent, (ast.Assign, ast.AnnAssign)) else None

        if not any(isinstance(binder, ast.arg) for binder in binders):
            # At least one initialization must dominate this construction.
            child, parent = creation, self.parents.get(creation)
            established = False
            while parent is not None and parent is not scope:
                if immediate and isinstance(parent, ast.For) and child in parent.body:
                    established |= any(binder in set(ast.walk(parent.target)) for binder in binders)
                for _field, statements in ast.iter_fields(parent):
                    if isinstance(statements, list) and child in statements:
                        earlier = statements[:statements.index(child)]
                        established |= any(binding_statement(binder) in earlier for binder in binders)
                child, parent = parent, self.parents.get(parent)
            if parent is scope and isinstance(getattr(scope, 'body', None), list):
                earlier = scope.body[:scope.body.index(child)] if child in scope.body else ()
                established |= any(binding_statement(binder) in earlier for binder in binders)
            if not established:
                return False
        child = creation
        parent = self.parents.get(child)
        while parent is not None and parent is not scope:
            if not immediate and isinstance(parent, (ast.For, ast.AsyncFor, ast.While)):
                # A source-earlier store can execute again after construction.
                if any(not isinstance(binder, ast.arg) and binder in set(ast.walk(parent))
                       for binder in binders):
                    return False
            child, parent = parent, self.parents.get(parent)
        return True

    def generator_collection_retained(self, name, scope):
        """A private mutable collection must retain its members throughout consumption."""
        if scope is self.tree or name not in self.locals.get(scope, ()):
            return False
        binders = self.generator_binders.get(scope, {}).get(name, ())
        for node in ast.walk(scope):
            self.budget.spend()
            if not isinstance(node, ast.Name) or node.id != name:
                continue
            if node in binders and isinstance(node.ctx, ast.Store):
                continue
            parent = self.parents.get(node)
            # Iteration and indexing do not release entries or expose the
            # container itself. Aliases, calls, attributes, returns and all
            # item writes require a separate ownership/mutation model.
            if (isinstance(node.ctx, ast.Load)
                    and (isinstance(parent, (ast.For, ast.comprehension)) and parent.iter is node
                         or isinstance(parent, ast.Subscript) and parent.value is node
                         and isinstance(parent.ctx, ast.Load))):
                continue
            return False
        return True

    def generator_literal_binding(self, name):
        """Recover immutable scalar/tuple initializers hidden by symbolic globals."""
        binders = self.generator_binders.get(self.tree, {}).get(name, ())
        if len(binders) != 1 or not isinstance(binders[0], ast.Name):
            return False
        statement = self.parents.get(binders[0])
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)) or statement not in self.tree.body:
            return False

        def immutable(value):
            if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                    and value.func.id == 'frozenset' and 'frozenset' not in self.global_names
                    and not value.keywords and len(value.args) == 1
                    and isinstance(value.args[0], (ast.Set, ast.Tuple, ast.List))
                    and all(immutable(item) for item in value.args[0].elts)
                    and not any(engine.generator_namespace_exposed or engine.generator_execution_capabilities
                                or 'frozenset' in engine.generator_attribute_writes for engine in self.generator_peers)):
                return True
            return (isinstance(value, ast.Constant)
                    or isinstance(value, ast.Tuple) and all(immutable(item) for item in value.elts)
                    or isinstance(value, ast.UnaryOp) and isinstance(value.op, (ast.UAdd, ast.USub, ast.Invert))
                    and isinstance(value.operand, ast.Constant)
                    and isinstance(value.operand.value, (int, float, complex)))

        return immutable(statement.value)

    def generator_helper_identity(self, function):
        """A delayed helper must not escape through an unmodeled metadata writer."""
        if function not in self.generator_helper_proofs:
            owner = self.enclosing(function)
            proven = isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and owner is not None
            if proven:
                for node in _scope_nodes(owner):
                    self.budget.spend()
                    if isinstance(node, ast.Name) and node.id == function.name:
                        parent = self.parents.get(node)
                        if not (isinstance(node.ctx, ast.Load) and isinstance(parent, ast.Call)
                                and parent.func is node):
                            proven = False
                            break
            self.generator_helper_proofs[function] = proven
        return (self.generator_helper_proofs[function]
                and not any(engine.generator_attribute_writes & {'__code__', '__defaults__', '__kwdefaults__'}
                            for engine in self.generator_peers))

    def generator_readonly_frame(self, capability):
        """Recognize unescaped stack inspection, never a writable frame map."""
        if (not isinstance(capability, ast.Attribute) or capability.attr != '_getframe'
                or not isinstance(capability.value, ast.Name)):
            return False
        module_name = capability.value.id
        imports = self.generator_binders[self.tree].get(module_name, ())
        if (len(imports) != 1 or not isinstance(imports[0], ast.Import) or imports[0] not in self.tree.body
                or not any(alias.name == 'sys' and (alias.asname or alias.name) == module_name
                           for alias in imports[0].names)
                or any(module_name in binders for scope, binders in self.generator_binders.items()
                       if scope is not self.tree)
                or {'_getframe', '__class__', 'getattr', 'hasattr'} & self.generator_attribute_writes):
            return False
        # Spelling alone cannot prove a standard frame. A replaced/imported
        # alias or exposed module dictionary keeps the acquisition unresolved.
        for node in ast.walk(self.tree):
            if (isinstance(node, ast.Name) and node.id in {
                    'globals', 'locals', 'vars', 'setattr', 'delattr', 'exec', 'eval', '__import__', '__builtins__'}
                    or isinstance(node, ast.Attribute) and node.attr in {
                        '__dict__', '__getattribute__', '__globals__', '__import__', '__builtins__',
                        'f_globals', 'f_locals', 'import_module'}
                    or isinstance(node, ast.Import) and any(alias.name.split('.')[0] == 'importlib'
                                                           for alias in node.names)
                    or isinstance(node, ast.ImportFrom) and node.module
                    and node.module.split('.')[0] == 'importlib'):
                return False
            if isinstance(node, ast.Name) and node.id == module_name and isinstance(node.ctx, ast.Load):
                parent = self.parents.get(node)
                if isinstance(parent, ast.Attribute) and parent.value is node:
                    continue
                if (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name)
                        and parent.func.id in {'getattr', 'hasattr'} and len(parent.args) >= 2 and parent.args[0] is node
                        and not any(parent.func.id in binders for binders in self.generator_binders.values())
                        and isinstance(parent.args[1], ast.Constant)
                        and parent.args[1].value not in {'__dict__', '__getattribute__', '_getframe'}):
                    continue
                return False
        call = self.parents.get(capability)
        assignment = self.parents.get(call)
        scope = self.enclosing(capability)
        if (not isinstance(call, ast.Call) or call.func is not capability or call.args or call.keywords
                or not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1
                or not isinstance(assignment.targets[0], ast.Name)
                or not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))):
            return False
        target = assignment.targets[0]
        for node in ast.walk(scope):
            if isinstance(node, (ast.Global, ast.Nonlocal)) and target.id in node.names:
                return False
            if not isinstance(node, ast.Name) or node.id != target.id or node is target:
                continue
            parent = self.parents.get(node)
            if isinstance(node.ctx, ast.Load):
                if (not isinstance(parent, ast.Attribute) or parent.value is not node
                        or not isinstance(parent.ctx, ast.Load) or parent.attr not in {'f_code', 'f_back'}):
                    return False
                if parent.attr == 'f_code':
                    continue
                transfer = self.parents.get(parent)
            else:
                transfer = parent
            # Walking f_back may replace only the very same local. Returning
            # it, passing it onward or copying it to an alias exposes a frame.
            destination = (transfer.targets[0] if isinstance(transfer, ast.Assign)
                           and len(transfer.targets) == 1 else
                           transfer.target if isinstance(transfer, ast.NamedExpr) else None)
            value = getattr(transfer, 'value', None)
            if (not isinstance(destination, ast.Name) or destination.id != target.id
                    or not isinstance(value, ast.Attribute) or value.attr != 'f_back'
                    or not isinstance(value.value, ast.Name) or value.value.id != target.id):
                return False
        return True

    def describe_framework(self, function, default_inputs, bindings, route, route_dependencies,
                           *, native_builtins=False):
        inputs = {}
        for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
            description = (default_inputs.get(arg.arg)
                           or _framework_input(arg.annotation, bindings, annotation_strings=True))
            if description is None:
                description = _FrameworkInput('source' if route else 'implicit', 'fastapi.request')
            if description is not None:
                # A plain FastAPI string parameter is converted by framework
                # invocation. Require the stable builtin spelling: postponed
                # annotations can resolve an alias after its definition, at
                # which point it may contain a custom validator. Reflected
                # namespace writes also prevent this primitive proof.
                native_string = (route and native_builtins and description.kind == 'source'
                                 and isinstance(arg.annotation, ast.Name)
                                 and arg.annotation.id == 'str'
                                 and 'str' not in self.global_names
                                 and 'str' not in self.generator_external_writers
                                 and not self.generator_namespace_exposed
                                 and not self.framework_annotation_metadata
                                 and bindings.get(arg.annotation.id, _implicit_identity(arg.annotation.id))
                                 in {'str', 'builtins.str'})
                inputs[arg.arg] = _FrameworkInput(description.kind, description.name,
                                                  description.dependency, native_string)
        # Capture import identities at the definition, before later rebinding.
        self.define('framework_inputs', function, inputs)
        self.define('framework_dependencies', function, tuple(route_dependencies))

    def define(self, table, node, value):
        """Record a definition-time table entry; a reused job replays it."""
        self.publish(table, node, value)
        if self.writes is not None:
            self.writes.append((table, node, value))

    def publish(self, table, key, value):
        destination = getattr(self, table)
        if self.journal is not None:
            self.journal.setdefault((id(destination), key),
                                    (destination, key, destination.get(key, _MISSING)))
        if self.local_journal is not None:
            self.local_journal.setdefault((id(destination), key),
                                          (destination, key, destination.get(key, _MISSING)))
        destination[key] = value

    def scope_name(self, scope):
        if isinstance(scope, ast.Module):
            return '<module>'
        location = self.scope_diagnostic(scope, '')
        prefix = f'{self.source_path}: ' if self.source_path is not None else ''
        return (f'{prefix}{location["symbol"]} '
                f'(lines {location["start_line"]}-{location["end_line"]})')

    def scope_diagnostic(self, scope, reason):
        """Keep source coordinates separate from a bounded human summary."""
        if isinstance(scope, ast.Module):
            end = max((getattr(statement, 'end_lineno', self.line_offset + 1)
                       for statement in scope.body), default=self.line_offset + 1)
            return {'file': str(self.source_path) if self.source_path is not None else '<module>',
                    'symbol': '<module>', 'start_line': 1, 'end_line': max(1, end - self.line_offset),
                    'reason': reason}
        names = [getattr(scope, 'name', '<lambda>')]
        parent = self.enclosing(scope)
        while parent is not None and not isinstance(parent, ast.Module):
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(parent.name)
            parent = self.enclosing(parent)
        start = scope.lineno - self.line_offset
        end = getattr(scope, 'end_lineno', scope.lineno) - self.line_offset
        return {'file': str(self.source_path) if self.source_path is not None else '<module>',
                'symbol': '.'.join(reversed(names)), 'start_line': start, 'end_line': end,
                'reason': reason}

    def interrupted_effects(self, function, flow):
        """Keep established base findings when a later context is interrupted."""
        effects = {}
        previous = self.observed_effects.get(function, ())
        prefix = ((*key, fact) for key, fact in flow.effects.items()) if flow is not None else ()
        for kind, line, column, label, fact in (*previous, *prefix):
            key = (kind, line, column, label)
            effects[key] = join_facts(effects.get(key, CLEAN), fact)
        return tuple((*key, fact) for key, fact in effects.items())

    def interrupted_summary(self, function, flow, budget):
        """Recover bounded observations across contexts, never their proofs."""
        budget.spend(len(self.summaries))
        previous = [summary for key, summary in self.summaries.items()
                    if (key[0] if isinstance(key, tuple) else key) is function]
        effects, mutations = {}, {}
        cells, global_writes = {}, {}
        returned, yielded, raised, returned_refs, yielded_refs = [], [], [], set(), set()
        capture_globals = set()

        def retain_effects(items):
            for kind, line, column, label, fact in items:
                key = (kind, line, column, label)
                budget.spend(1 + len(fact) + len(effects.get(key, CLEAN)))
                effects[key] = join_facts(effects.get(key, CLEAN), fact)

        def retain_mutations(items):
            for ref, fact in items:
                if isinstance(ref, str):
                    budget.spend(1 + len(fact) + len(mutations.get(ref, CLEAN)))
                    mutations[ref] = join_facts(mutations.get(ref, CLEAN), fact)

        def retain_cells(items):
            for ref, contents in items:
                budget.spend(1 + len(contents.fact) + len(contents.references))
                retained = _CellContents(contents.fact, contents.references, None, None)
                previous = cells.get(ref)
                cells[ref] = retained if previous is None else _join_cells(previous, retained)

        def retain_globals(items):
            for module, name, contents in items:
                budget.spend(1 + len(contents.fact) + len(contents.references))
                retained = _CellContents(contents.fact, contents.references, None)
                key = (module, name)
                previous = global_writes.get(key)
                global_writes[key] = retained if previous is None else _join_cells(previous, retained)

        def retain_observations(items, facts, references=None):
            budget.spend(len(items))
            for fact, refs in items:
                budget.spend(len(fact) + len(refs)
                             + sum(len(flow.mutations.get(ref, CLEAN)) for ref in refs))
                facts.append(fact)
                facts.extend(flow.mutations.get(ref, CLEAN) for ref in refs)
                if references is not None:
                    references.update(ref for ref in refs if isinstance(ref, str))

        def retain_defaults(binding, facts, references):
            pending = [binding]
            while pending:
                binding = pending.pop()
                for value in _binding_choices(binding):
                    if isinstance(value, _ClosureValue):
                        pending.append(value.value)
                        budget.spend(1 + len(value.cells))
                        for _name, ref in value.cells:
                            contents = cells.get(ref)
                            if contents is not None:
                                facts.append(contents.fact)
                                references.update(obj for obj in contents.references if isinstance(obj, str))
                        continue
                    if not isinstance(value, _FunctionValue):
                        continue
                    budget.spend(1 + len(value.arguments) + len(value.references) + len(value.values))
                    default_refs = dict(value.references)
                    for name, fact in value.arguments:
                        refs = default_refs.get(name, NO_REFERENCES)
                        budget.spend(len(fact) + len(refs))
                        facts.append(fact)
                        references.update(ref for ref in refs if isinstance(ref, str))
                        if flow is not None:
                            budget.spend(sum(len(flow.mutations.get(ref, CLEAN)) for ref in refs))
                            facts.extend(flow.mutations.get(ref, CLEAN) for ref in refs)
                    pending.extend(captured for _, captured in value.values)

        for summary in previous:
            budget.spend(len(summary.capture_globals))
            capture_globals.update(summary.capture_globals)
            retain_effects(summary.effects)
            retain_mutations(summary.mutations)
            retain_cells(summary.cells)
            retain_globals(summary.global_writes)
            budget.spend(len(summary.returned) + len(summary.yielded)
                         + len(summary.returned_references) + len(summary.yielded_references))
            returned.append(summary.returned)
            yielded.append(summary.yielded)
            returned_refs.update(summary.returned_references)
            yielded_refs.update(summary.yielded_references)
            retain_defaults(summary.returned_binding, returned, returned_refs)
            retain_defaults(summary.yielded_binding, yielded, yielded_refs)
            for exception in summary.exceptions:
                retain_mutations(exception.mutations)
                retain_cells(exception.cells)
                retain_globals(exception.global_writes)
                budget.spend(1 + len(exception.value))
                raised.append(exception.value)
        retain_effects(self.partial_scope_effects.get(function, ()))
        if flow is not None:
            retain_globals((self.tree, name, _CellContents(
                join_facts(contents.fact, *(flow.mutations.get(ref, CLEAN) for ref in contents.references)),
                contents.references, None))
                for name, contents in (flow.observed_global_writes or {}).items())
            observed_states = (flow.last_state, flow.normal_state, flow.yielded_state,
                               *(item.state for item in flow.pending))
            for state in observed_states:
                if state is not None and state.cells is not None:
                    retain_cells((ref, _CellContents(
                        join_facts(contents.fact, *(state.heap.get(obj, CLEAN) for obj in contents.references)),
                        contents.references, None, None)) for ref, contents in state.cells.contents.items())
            budget.spend(len(flow.capture_globals))
            capture_globals.update(flow.capture_globals)
            retain_mutations(flow.mutations.items())
            budget.spend(len(flow.observed_returns))
            observations = [(flow.returned, flow.returned_references), *flow.observed_returns,
                            (flow.yielded, flow.yielded_references)]
            retain_observations(observations, returned, returned_refs)
            retain_observations(flow.observed_raises, raised)
            for binding in (*flow.returned_bindings, *flow.observed_return_bindings):
                retain_defaults(binding, returned, returned_refs)
            for binding in flow.yielded_bindings:
                retain_defaults(binding, yielded, yielded_refs)
        return FunctionSummary(
            returned=join_facts(*returned), yielded=join_facts(*yielded),
            effects=tuple((*key, fact) for key, fact in effects.items()),
            mutations=tuple(mutations.items()),
            returned_references=frozenset(returned_refs), yielded_references=frozenset(yielded_refs),
            exceptions=(ExceptionSummary(None, join_facts(*raised)),) if raised else (),
            returned_binding=None, yielded_binding=None, can_return=True, incomplete=True,
            capture_globals=frozenset(capture_globals),
            cells=tuple(cells.items()), multiple_cells=frozenset(cells),
            global_writes=tuple((module, name, contents)
                                for (module, name), contents in global_writes.items()),
        )

    def framework_summary_key(self, function):
        owner = self.owner(function)
        if function in owner.failed_scopes:
            return function
        required = self.summaries.get(function, FunctionSummary()).value_parameters
        context = tuple(sorted((name, _GeneratorString())
                               for name, description in owner.framework_inputs.get(function, {}).items()
                               if description.native_string and name in required))
        return (function, context) if context else function

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
            self.budget.spend()
            changed = False
            for function, inputs in self.framework_inputs.items():
                for name, description in inputs.items():
                    provider = description.dependency
                    if provider is None:
                        continue
                    owner = self.owner(provider)
                    # A failed foreign callback context can be rolled out of
                    # the project's shared table. Its owner's quarantine is
                    # authoritative even when an earlier complete summary was
                    # restored there for unrelated import components.
                    summary = owner.failed_summaries.get(provider)
                    if summary is None:
                        summary = self.summaries.get(provider, FunctionSummary())
                    delivered = summary.yielded if provider in owner.generators else summary.returned
                    provider_globals = (global_bound if owner is self else
                                        {f'@global:{key}': owner.globals.value(key) for key in owner.globals})
                    provider_inputs = bound.get(provider, {}) if owner is self else owner.framework_values.get(provider, {})
                    incoming = self.flow_class.substitute(delivered, {**provider_globals, **provider_inputs},
                                                         provider.name + '()', budget=self.budget)
                    if summary.incomplete:
                        # Dependency injection calls the provider without the
                        # ordinary incomplete_call transfer. Give it the same
                        # opaque return policy: observed returns cannot retain
                        # sanitizer proof, and an unvisited return may expose
                        # an incoming request value or module global.
                        possible = [incoming, *provider_inputs.values(), *provider_globals.values()]
                        if owner is not self:
                            # An imported helper may first become a dependency
                            # here; its own module did not necessarily have a
                            # Depends edge activating implicit request inputs.
                            for parameter, input_ in owner.framework_inputs.get(provider, {}).items():
                                if input_.kind in {'source', 'implicit'} and parameter not in provider_inputs:
                                    possible.append(frozenset({TaintTrace(input_.name,
                                        path=(input_.name, parameter))}))
                        self.budget.spend(sum(len(fact) for fact in possible))
                        incoming = self.flow_class.incomplete_result(join_facts(*possible))
                    previous = bound[function].get(name, CLEAN)
                    updated = join_facts(previous, incoming)
                    if updated != previous:
                        bound[function][name] = updated
                        changed = True
            if not changed:
                return bound

    def callable_context(self, name, binding, *, captured=False, value_parameters=()):
        """Finite callable/argv/process identity; captured facts use slots."""
        choices = []
        if name in value_parameters:
            for value in _binding_choices(binding):
                if isinstance(value, _ArgumentVector):
                    self.budget.spend(sum(len(refs) for refs in value.references))
        variants = ({shape: index for index, shape, _vectors in _vector_variants(binding)}
                    if name in value_parameters else {})
        for value in _binding_choices(binding):
            if isinstance(value, (_DeferredGenerator, _GeneratorNext)):
                raise AnalysisLimit('generator passed through a callable context; analysis is incomplete')
            if isinstance(value, _GlobalNamespace):
                raise AnalysisLimit('globals mapping captured by a callable; analysis is incomplete')
            if isinstance(value, _CellGraph):
                self.budget.spend(len(value.entries))
                value = _CellGraph(value.roots, tuple(
                    (slot, self.callable_context(slot, child, captured=True, value_parameters=value_parameters),
                     bound, multiple) for slot, child, bound, multiple in value.entries))
            elif isinstance(value, _ClosureValue):
                if any(not isinstance(ref, str) for _name, ref in value.cells):
                    raise AnalysisLimit('unnormalized lexical callback context; analysis is incomplete')
                self.budget.spend(len(value.cells))
                value = _ClosureValue(self.callable_context(name, value.value, captured=captured,
                                                           value_parameters=value_parameters), value.cells)
            elif isinstance(value, _FunctionValue):
                self.budget.spend(1 + len(value.arguments))
                arguments, references, bindings = [], [], []
                default_values = dict(value.values)
                for parameter, _fact in value.arguments:
                    slot = f'@default:{name}:{parameter}'
                    symbolic = frozenset({TaintTrace(slot, parameter=slot, path=(slot,))})
                    arguments.append((parameter, symbolic))
                    references.append((parameter, frozenset({slot})))
                    bindings.append((parameter, self.callable_context(
                        slot, default_values.get(parameter), captured=True, value_parameters=value_parameters)))
                value = type(value)(value.function, tuple(arguments), tuple(references), tuple(bindings))
            elif isinstance(value, (_BoundCallable, _BoundClassMethod)):
                slot = '@method:' + name
                symbolic = frozenset({TaintTrace(slot, parameter=slot, path=(slot,))})
                qualified = value.name if isinstance(value, _BoundCallable) else None
                if qualified:
                    qualified = _opaque_qualifier(qualified, receiver_unknown=not value.namespace_proven)
                function = (self.callable_context(name, value.function, captured=captured,
                                                  value_parameters=value_parameters)
                            if isinstance(value, _BoundClassMethod) else None)
                value = (_BoundClassMethod(function, value.owner, frozenset({slot}), symbolic, value.valid)
                         if isinstance(value, _BoundClassMethod)
                         else _BoundCallable(qualified, frozenset({slot}), symbolic, value.namespace_proven))
            elif isinstance(value, _ArgumentVector) and name in value_parameters:
                value = _context_vector(value)
                shape = _vector_shape(value)
                variant = variants[shape]
                self.budget.spend(len(shape))
                operands, references = [], []
                for index, operand in enumerate(shape):
                    slot = _vector_slot(name, variant, index)
                    symbolic = frozenset({TaintTrace(slot, parameter=slot,
                                                     path=(slot, f'{name}[{index}]'))})
                    operands.append((operand if operand is not None else _SymbolicValue(slot), symbolic))
                    references.append(NO_REFERENCES if isinstance(operand, _LiteralString) else frozenset({slot}))
                value = _ArgumentVector(tuple(operands), tuple(references))
            elif isinstance(value, _LiteralString) and name in value_parameters:
                pass
            elif isinstance(value, _GeneratorString) and (captured or name in value_parameters):
                # Ownership proofs need this identity; ordinary dataflow
                # parameters must keep sharing their symbolic summaries.
                pass
            elif isinstance(value, ast.Constant) and name in value_parameters:
                # Partial captures may retain exact scalar options such as
                # shell=False. Their source AST identities are finite.
                pass
            elif not isinstance(value, (str, _LiteralMapping, _ProcessInput, ast.FunctionDef, ast.AsyncFunctionDef,
                                        ast.Lambda, ast.ClassDef)):
                value = _SymbolicValue(name) if captured else None
            choices.append(value)
        return _join_bindings(*choices)

    def call_summary(self, function, values, candidate_keys=None, global_overrides=(), *, cell_context=None):
        # A provisional summary may discover a captured global only through
        # another helper. Follow those ordinary summary dependencies until
        # this call's context includes the captures it actually reads. Each
        # read participates in the existing fixed point and every expansion
        # adds a finite, module-qualified dependency.
        required = frozenset()
        required_values = frozenset()
        while True:
            contextual, keys = cell_context(required) if cell_context is not None else (values, candidate_keys)
            summary = self._call_summary(function, contextual, keys,
                                         global_overrides, required, required_values)
            self.budget.spend(len(required) + len(summary.capture_globals)
                              + len(required_values) + len(summary.value_parameters))
            missing = summary.capture_globals - required
            missing_values = summary.value_parameters - required_values
            if not missing and not missing_values:
                return summary
            required = required | missing
            required_values = required_values | missing_values

    def _call_summary(self, function, values, candidate_keys=None, global_overrides=(),
                      capture_globals=frozenset(), value_parameters=frozenset()):
        """Request a symbolic summary for known callable and argv identities.

        Facts, heaps and evidence paths are NOT context keys. Only finite
        source-level identities and bounded argv shapes distinguish invocations.
        Unresolved alternatives stay opaque rather than certifying a sanitizer. A new
        context starts at bottom and is solved by the normal fixed-point
        loop, never by recursively interpreting callees on the Python stack.
        """
        owner = self.owner(function)
        if function in owner.failed_scopes:
            summary = owner.failed_summaries[function]
            if self.summaries.get(function) is not summary:
                self.publish('summaries', function, summary)
            if self.reads is not None:
                self.reads[('summaries', function)] = summary
            return summary
        context = []
        direct_globals = owner.used_names[function]
        owner_fn = None
        owner_bindings = None
        # Candidate names can come from both a lexical global and an inherited
        # callback context. They describe one mapping, not repeated arguments:
        # retaining duplicate entries creates a fresh, longer context on every
        # recursive call even though no callable identity changed.
        if candidate_keys is not None and capture_globals:
            candidate_keys = dict.fromkeys(candidate_keys)
            candidate_keys.update((f'@global:{name}', None) for module, name in capture_globals
                                  if module is owner.tree)
            candidate_keys.update((f'@presence:{name}', None) for module, name in capture_globals
                                  if module is owner.tree and name in owner.namespace_read_names)
        items = ((name, values.get(name)) for name in dict.fromkeys(candidate_keys)) if candidate_keys is not None else values.items()
        for name, binding in items:
            if name.startswith('@default:'):
                continue  # Captures are carried by the enclosing callback identity.
            if name.startswith('@presence:'):
                if (name[10:] in owner.namespace_read_names
                        and (owner.tree, name[10:]) in capture_globals):
                    # Membership is a separate finite context dimension. An
                    # existing opaque/None value is not an absent mapping key.
                    context.append((name, binding if binding in {
                        _NAMESPACE_PRESENT, _NAMESPACE_ABSENT, _NAMESPACE_MAYBE} else _NAMESPACE_MAYBE))
                continue
            if name.startswith('@global:'):
                gname = name[8:]
                if (direct_globals is not None and gname not in direct_globals
                        and (owner.tree, gname) not in capture_globals):
                    continue
                # A caller may replace a global callable or class method and
                # restore it later. The module's final binding cannot certify
                # a call made while that identity was replaced. Preserve the
                # finite identity (including its revoked/unknown alternative)
                # through helper calls, just as for callback parameters.
                if owner_fn is None:
                    owner_fn = self.owner(function)
                    owner_bindings = owner_fn.globals.bindings
                # The initial empty namespace is not a nominal binding. Its
                # first publication (also used by import-cycle priming) makes
                # these comparisons meaningful; the module then runs again.
                if not owner_fn.namespace_ready:
                    continue
                nominal = owner_bindings.get(gname)
                explicit_override = gname in global_overrides
                if (not explicit_override and (owner_fn.tree, gname) not in capture_globals
                        and any(isinstance(value, (_FunctionValue, _ClosureValue, _BoundCallable))
                                for value in _binding_choices(binding))
                        and _same_witness(binding, nominal)):
                    continue
                if (binding is nominal
                        and not isinstance(binding, (frozenset, _BoundCallable, _BoundClassMethod, _FunctionValue, _ClosureValue,
                                                     _ArgumentVector, _LiteralString, _GeneratorString, _LiteralMapping, _ProcessInput))
                        and not explicit_override
                        and gname in owner_bindings
                        and gname not in owner_fn.locals[function]
                        and gname not in owner_fn.closures[function]):
                    # Ordinary unchanged globals do not distinguish a call.
                    # Avoid constructing choices only to discard them below;
                    # bound receivers and alternatives still need normalization.
                    continue
                if not explicit_override and not any(
                        isinstance(value, (str, ast.FunctionDef, ast.AsyncFunctionDef,
                                           ast.Lambda, ast.ClassDef, _BoundCallable, _BoundClassMethod, _FunctionValue, _ClosureValue,
                                           _ArgumentVector, _LiteralString, _GeneratorString, _LiteralMapping, _ProcessInput, ast.Constant))
                        for value in (*_binding_choices(binding), *_binding_choices(nominal))):
                    continue
            elif binding is None or isinstance(binding, _SymbolicValue):
                continue
            required_values = value_parameters
            if name.startswith('@global:') and (explicit_override or (owner.tree, gname) in capture_globals):
                required_values = required_values | {name}
            choices = _binding_choices(self.callable_context(name, binding, value_parameters=required_values))
            if name.startswith('@global:'):
                joined_choice = _join_bindings(*choices)
                if (joined_choice is nominal
                        and not explicit_override
                        and gname in owner_bindings
                        and gname not in owner_fn.locals[function]
                        and gname not in owner_fn.closures[function]):
                    continue
                # A contextual call keeps its explicit overrides through
                # recursion, even if provisional module initialization now
                # happens to match them. The base summary may still describe
                # the preceding namespace; merging into it would import stale
                # effects into an otherwise independent recursive context.
                context.append((name, joined_choice))
            elif any(value is not None for value in choices):
                context.append((name, _join_bindings(*choices)))
        if len(context) > 1:
            context.sort(key=lambda item: item[0])
        key = (function, tuple(context)) if context else function
        summary = self.summaries.get(key)
        if summary is None:
            summary = FunctionSummary()
            self.publish('summaries', key, summary)
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

    def solve_function(self, function, context):
        """Solve one summary, keeping definition-time collectors exception safe."""
        owner = self.owner(function)
        reads = {('framework_inputs', function): owner.framework_inputs.get(function)}
        writes = []
        owner.reads, owner.writes = reads, writes
        total_budget = owner.budget
        owner.budget = _ScopedBudget(owner, function, total_budget)
        owner.local_journal = {}
        flow = None
        try:
            owner.budget.spend()
            namespace = owner.globals
            local = owner.locals[function]
            used = owner.used_names[function]
            flow = owner.flow_class(owner, function)
            state = _State()
            # Most functions read a few names in a potentially large module.
            # Probe those dependencies rather than scanning all globals for
            # every solve. Namespace bindings can also come from a star
            # import, so retain them even without a static global symbol.
            for name in used:
                if name in local:
                    continue
                symbolic = owner.global_symbols.get(name)
                if symbolic is not None:
                    state[name] = symbolic[0]
                    state.references[name] = symbolic[1]
                binding = namespace.bindings.get(name, _MISSING)
                if binding is not _MISSING:
                    state.bindings[name] = binding
                if _namespace_presence(namespace, name) != _NAMESPACE_PRESENT:
                    state.maybe_unbound = state.maybe_unbound | {name}
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
                cells = state.cell_state()
                cells.names[name] = f'@free:{name}'
                cells.contents[f'@free:{name}'] = _CellContents(
                    state[name], state.references[name], state.bindings[name])
            if context:
                ctx_globals = []
                cell_graph = None
                for name, binding in context:
                    if name == '@cells':
                        cell_graph = binding
                        continue
                    if name.startswith('@presence:'):
                        state.bindings[name] = binding
                        raw = name[10:]
                        symbolic = owner.global_symbols.get(raw)
                        if symbolic is not None:
                            slot = '@global:' + raw
                            state.setdefault(slot, symbolic[0])
                            state.references.setdefault(slot, symbolic[1])
                            value = (namespace.bindings.get(raw) if raw in local or raw in owner.closures[function]
                                     else state.bindings.get(raw, namespace.bindings.get(raw)))
                            state.bindings.setdefault(slot, value)
                        continue
                    raw = name.removeprefix('@free:').removeprefix('@global:')
                    if name.startswith('@global:') and (raw in local or raw in owner.closures[function]):
                        # A module value cannot replace a same-spelled argument
                        # or closure cell. Reflective global reads still use
                        # their separate, module-qualified slot.
                        if raw in owner.global_symbols:
                            state[name] = owner.global_symbols[raw][0]
                            state.references[name] = owner.global_symbols[raw][1]
                        state.bindings[name] = binding
                        continue
                    if name.startswith('@global:') and raw in owner.global_symbols and raw not in local:
                        state.setdefault(raw, owner.global_symbols[raw][0])
                        state.references.setdefault(raw, owner.global_symbols[raw][1])
                        ctx_globals.append(raw)
                    state.bindings[raw] = binding
                if ctx_globals:
                    flow.context_globals = tuple(ctx_globals)
                if isinstance(cell_graph, _CellGraph):
                    cells = state.cell_state()
                    for slot, binding, present, multiple in cell_graph.entries:
                        symbolic = frozenset({TaintTrace(slot, parameter=slot, path=(slot,))})
                        cells.contents[slot] = _CellContents(symbolic, frozenset({slot}), binding, present)
                        if multiple:
                            cells.multiple.add(slot)
                    for name, slot in cell_graph.roots:
                        cells.names[name] = slot
                        state.put_cell(slot, cells.contents[slot])
            # A cell exists for the whole defining invocation, including
            # branches that have not yet created a closure. Allocating these
            # exact cell variables here also models uninitialized/deleted
            # locals without borrowing a same-spelled caller value.
            for name in owner.cell_locals.get(function, ()):
                cells = state.cell_state()
                ref = _CellRef(function, name)
                cells.names[name] = ref
                cells.contents[ref] = _CellContents(state.get(name, CLEAN),
                                                    state.references.get(name, NO_REFERENCES),
                                                    state.bindings.get(name), name in state)
            if isinstance(function, ast.Lambda):
                flow.exception_states.append(None)
                flow.returned = flow.expr(function.body, state)
                exceptional = flow.exception_states.pop()
                if exceptional is not None:
                    flow.pending.append(_Completion('raise', exceptional))
                flow.normal_state = state if state.reachable else None
                flow.returned_references.update(flow.expression_references.get(function.body, NO_REFERENCES))
                flow.returned_bindings.append(flow.expression_bindings.get(function.body))
            else:
                if function.name in used and function.name not in local and function.name not in state.bindings:
                    state.bindings[function.name] = function
                flow.normal_state, completed = flow.capture(function.body, state, exceptions=True)
                flow.pending.extend(completed)
            return reads, writes, flow.summary()
        except AnalysisLimit as exc:
            diagnostics = exc.components or (owner.scope_diagnostic(function, str(exc)),)
            # A total cutoff leaves no allowance for either recovery or
            # independent functions. Semantic failures and per-function
            # cutoffs instead quarantine only this body and all its contexts.
            if total_budget.remaining < 0:
                self.observed_effects[function] = owner.interrupted_effects(function, flow)
                raise AnalysisLimit(f'{owner.scope_name(function)}: {exc}',
                                    effects=exc.effects, components=diagnostics) from exc
            # A failed body may have installed provisional callback contexts
            # or nested defaults. Roll them back before other scopes run.
            for table, key, previous in owner.local_journal.values():
                if previous is _MISSING:
                    table.pop(key, None)
                else:
                    table[key] = previous
            owner.partial_scope_effects[function] = owner.interrupted_effects(function, flow)
            owner.observed_effects[function] = owner.partial_scope_effects[function]
            # Recovery consumes the remaining file allowance, not a fresh
            # function allowance. Include completed callback contexts before
            # invalidating them so their concrete observations survive too.
            try:
                failed = owner.interrupted_summary(function, flow, total_budget)
            except AnalysisLimit as recovery:
                # A caller may be solving a context owned by an already-ready
                # imported module. Its outer failure collector belongs to this
                # analysis, so retain the foreign prefix here as well.
                self.observed_effects[function] = owner.partial_scope_effects[function]
                raise AnalysisLimit(
                    f'{owner.scope_name(function)}: UBS_PYTHON_FLOW_MAX_STEPS={owner.work_limit}: {recovery}',
                    effects=recovery.effects,
                    components=(*diagnostics, *(recovery.components or (
                        owner.scope_diagnostic(function, str(recovery)),))),
                ) from recovery
            owner.failed_summaries[function] = failed
            reason = str(exc) if isinstance(exc, _ScopeIncomplete) else f'{owner.scope_name(function)}: {exc}'
            owner.failed_scopes[function] = reason
            owner.failed_scope_diagnostics[function] = diagnostics
            owner.partial_scope_effects[function] = owner.failed_summaries[function].effects
            if isinstance(exc, _ScopeIncomplete):
                raise
            raise _ScopeIncomplete(reason, effects=exc.effects, components=diagnostics) from exc
        finally:
            owner.reads = owner.writes = None
            owner.local_journal = None
            owner.budget = total_budget

    def _escaping_namespace_factory(self):
        """Check settled return/capture bindings once, without executing code."""
        pending = list(self.escaping_callables)
        seen_values, seen_functions = set(), set()
        while pending:
            self.budget.spend()
            value = pending.pop()
            if id(value) in seen_values:
                continue
            seen_values.add(id(value))
            if isinstance(value, _GlobalNamespace):
                return True
            if isinstance(value, str) and value in ('globals', 'builtins.globals'):
                return True
            if (isinstance(value, _BoundCallable) and value.namespace_proven
                    and value.name in ('globals', 'builtins.globals')):
                return True
            if isinstance(value, _ClosureValue):
                pending.append(value.value)
                continue
            if isinstance(value, (_FunctionValue, _DeferredCall)):
                for _name, binding in value.values:
                    pending.extend(_binding_choices(binding))
                function = value.function
            elif isinstance(value, _BoundClassMethod):
                function = value.function
            elif isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                function = value
            else:
                continue
            if function in seen_functions:
                continue
            seen_functions.add(function)
            summary = self.owner(function).summaries.get(function)
            if summary is not None:
                pending.extend(_binding_choices(summary.returned_binding))
                pending.extend(_binding_choices(summary.yielded_binding))
        return False

    def analyze(self):
        try:
            return self._analyze()
        except AnalysisLimit as exc:
            # Rendering already observed concrete facts is linear in retained
            # work. Do not expand symbolic summaries after a total cutoff or
            # present these incomplete results as reusable function contracts.
            if not exc.effects:
                effects = {}
                for scope_effects in self.observed_effects.values():
                    for kind, line, column, label, fact in scope_effects:
                        concrete = frozenset(trace for trace in fact if trace.parameter is None
                                             and not _safe_for(trace, kind, label))
                        if concrete:
                            key = (kind, line, column, label)
                            effects[key] = join_facts(effects.get(key, CLEAN), concrete)
                exc.effects = effects
            if self.budget.remaining < 0:
                location = str(self.source_path) if self.source_path is not None else '<module>'
                exc.args = (f'{location}: UBS_PYTHON_FLOW_MAX_STEPS={self.work_limit}: {exc}',)
            if not exc.components:
                exc.components = (self.scope_diagnostic(self.tree, str(exc)),)
            previous = list(self.scope_diagnostics)
            for items in self.failed_scope_diagnostics.values():
                previous.extend(items)
            exc.components = _distinct_components((*previous, *exc.components))
            raise

    def _analyze(self):
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
        # the same summary and effects, so the previous ones are reused. Local
        # expression/heap states belong to the solve, not the summary cache.
        solved = {}  # summary key -> (reads, writes, latest base effects)
        namespace_inputs = {}
        readers = defaultdict(dict)
        # A write-free job can read defaults produced by a writer context.
        # Moving all writers ahead of it changes that read even when writer
        # order itself stays unchanged. Newly requested contexts may belong
        # to foreign owners, so retain the whole source-order snapshot when
        # any selected owner can write shared definition-time tables.
        allow_reordering = not (self.definition_writers or any(
            owner.definition_writers for owner in set(self.function_owners.values())))
        # A nested definition preserves source-order jobs, but must not make
        # every settling link of an unrelated call chain execute the entire
        # module again. Cache the module transfer on its observed inputs just
        # like a function job. Replaying its writes in place preserves the
        # ordering of contextual defaults and class definitions. Active import
        # cycles keep the uncached path because peer namespaces can change.
        cache_module = not solving
        previous_module = None
        initializing = cache_module
        initializer_jobs = set()

        def parts(key):
            return key if isinstance(key, tuple) else (key, ())

        def namespace_input(key):
            function, _ = parts(key)
            owner = self.owner(function)
            required = self.summaries.get(key, FunctionSummary()).capture_globals
            if any(module is not owner.tree for module, _name in required):
                return None  # Foreign namespace changes retain the full solve.
            names = ((owner.used_names[function] - owner.locals[function])
                     | {name for _module, name in required})
            return (owner.namespace_ready, frozenset(owner.namespace_read_names)), {
                name: (owner.globals.bindings.get(name, _MISSING), _namespace_presence(owner.globals, name))
                for name in names}

        def namespace_current(key):
            before = namespace_inputs.get(key)
            after = namespace_input(key)
            return (before is not None and after is not None and before[0] == after[0]
                    and before[1].keys() == after[1].keys()
                    and all(_same_witness(value, after[1][name])
                            for name, value in before[1].items()))

        def replay(owner, writes):
            for table, node, value in writes:
                # Most declaration tables still hold these exact immutable
                # values. No write or rollback entry is needed in that case;
                # equality alone would discard a refreshed evidence witness.
                if getattr(owner, table).get(node, _MISSING) is not value:
                    owner.publish(table, node, value)

        def reorderable(key):
            function, _ = parts(key)
            owner = self.owner(function)
            if function in owner.failed_scopes:
                return False
            if (not isinstance(key, tuple) and owner is not self
                    and self.project is not None and owner in self.project.ready
                    and owner not in solving):
                # A ready module has solved every base function, including
                # nonreturning bottom summaries. Importers only need to solve
                # new callback contexts; active import cycles still converge.
                return False
            return (allow_reordering and key not in inherited
                    and function not in owner.definition_writers)

        while True:
            self.budget.spend()
            previous_contexts = len(self.summaries)
            reuse_module = False
            if cache_module and previous_module is not None:
                namespace, ready, reads, writes, module, globals_ = previous_module
                reuse_module = (ready == self.namespace_ready
                                and _same_namespace(namespace, self.globals)
                                and self.reads_current(reads))
            if reuse_module:
                replay(self, writes)
                # The equivalent current namespace is the same immutable
                # cache input; retain its identity for subsequent sweeps.
                previous_module = self.globals, ready, reads, writes, module, globals_
            else:
                namespace, ready = self.globals, self.namespace_ready
                reads, writes = {}, []
                saved_reads, saved_writes = self.reads, self.writes
                self.reads, self.writes = reads, writes
                try:
                    module = self.flow_class(self, self.tree)
                    try:
                        globals_ = module.block(self.tree.body, _State())
                    finally:
                        self.observed_effects[self.tree] = tuple(
                            (*key, fact) for key, fact in module.effects.items())
                    if globals_ is None:
                        # Keep definitions and global facts established before
                        # a nonreturning call as the callee's namespace.
                        globals_ = module.last_state if module.last_state is not None else _State()
                finally:
                    self.reads, self.writes = saved_reads, saved_writes
                if cache_module:
                    previous_module = namespace, ready, reads, writes, module, globals_
            # Imported higher-order helpers may call a callback defined by
            # this module. Publish this pass's namespace before solving those
            # contexts, and iterate again when initialization facts change.
            changed = not self.namespace_ready or globals_ != self.globals
            if changed and not cache_module:
                solved.clear()  # Every job of this module starts from the namespace.
                readers.clear()
                namespace_inputs.clear()
            self.refresh_globals(globals_)
            # Type coercion belongs to framework entry, not the callable's
            # ordinary summary. Request only demanded primitive contexts and
            # let their helper dependencies settle on this same worklist.
            for function in self.functions:
                key = self.framework_summary_key(function)
                if isinstance(key, tuple) and key not in self.summaries:
                    self.publish('summaries', key, FunctionSummary())
            if initializing:
                initializer_jobs.update(key for (table, key) in reads if table == 'summaries')
                if not initializer_jobs:
                    initializing = False
            jobs = [*self.functions, *(key for key in self.summaries
                                      if isinstance(key, tuple) and key not in inherited)]
            if initializing:
                jobs = [key for key in jobs if key in initializer_jobs]
            previous_initializer_jobs = len(initializer_jobs)
            pending, queued, dirty = deque(), set(), set()

            def enqueue(key):
                if reorderable(key):
                    dirty.add(key)
                    if key not in queued:
                        pending.append(key)
                        queued.add(key)

            def solve(summary_key):
                function, context = parts(summary_key)
                owner = self.owner(function)
                if function in owner.failed_scopes:
                    effects = owner.partial_scope_effects.get(function, ()) if not context and owner is self else ()
                    solved[summary_key] = ({}, [], effects)
                    return False
                previous = solved.get(summary_key)
                if (previous is not None and namespace_current(summary_key)
                        and owner.reads_current(previous[0])):
                    # Replay its definition-time writes, in job order, so later
                    # jobs read exactly what a fresh solve would have left.
                    replay(owner, previous[1])
                    return False
                if previous is not None:
                    for table, key in previous[0]:
                        if table == 'summaries':
                            readers[key].pop(summary_key, None)
                try:
                    reads, writes, summary = self.solve_function(function, context)
                except _ScopeIncomplete as exc:
                    self.scope_errors.append(str(exc))
                    self.scope_diagnostics.extend(exc.components)
                    # Revoke every context of this body, including a previous
                    # clean/nonreturning summary. Their readers must run again
                    # with the opaque-call continuation, not stale proof.
                    scope_effects = owner.partial_scope_effects.get(function, ())
                    failed = owner.failed_summaries[function]
                    keys = [key for key in self.summaries if parts(key)[0] is function]
                    for key in dict.fromkeys([function, *keys]):
                        owner.publish('summaries', key, failed)
                        for reader in readers[key]:
                            enqueue(reader)
                    if owner is self:
                        self.observed_effects[function] = scope_effects
                    solved[summary_key] = ({}, [], scope_effects if not context and owner is self else ())
                    return True
                # Keep this solve's witness even if semantic summary equality
                # avoids publication. Contextual effects are projected through
                # their callers, so they need no second cached representation.
                latest_effects = summary.effects if not context and owner is self else ()
                if not context and owner is self:
                    self.observed_effects[function] = latest_effects
                solved[summary_key] = (reads, writes, latest_effects)
                namespace_inputs[summary_key] = namespace_input(summary_key)
                for table, key in reads:
                    if table == 'summaries':
                        if initializing:
                            initializer_jobs.add(key)
                        readers[key][summary_key] = None
                        if key not in solved and reorderable(key):
                            enqueue(key)
                            # Keep the caller pending while a newly discovered
                            # dependency is still at bottom. Otherwise a chain
                            # of fresh callback contexts propagates each
                            # provisional prefix all the way back to its root.
                            if key != summary_key:
                                enqueue(summary_key)
                if summary != self.summaries.get(summary_key, FunctionSummary()):
                    self.publish('summaries', summary_key, summary)
                    for reader in readers[summary_key]:
                        enqueue(reader)
                    return True
                return False

            # Definition-time writes still happen in the original job order.
            # Only jobs without such writes may move ahead of their readers.
            # This preserves defaults/class tables even when contextual jobs
            # publish different definitions at the same syntax location.
            for key in jobs:
                if reorderable(key):
                    enqueue(key)
                else:
                    if solve(key):
                        changed = True

            # Follow observed summary dependencies before re-solving a caller.
            # Newly requested callback contexts join this same worklist. An
            # explicit stack handles long chains; an active back edge uses the
            # current approximation and requeues its readers on change.
            active, stack = set(), []
            while pending or stack:
                self.budget.spend()
                if not stack:
                    key = pending.popleft()
                    queued.remove(key)
                    if key not in dirty:
                        continue
                    stack.append(key)
                    active.add(key)
                key = stack[-1]
                previous = solved.get(key)
                dependency = None
                if previous is not None:
                    for table, candidate in previous[0]:
                        if table == 'summaries' and candidate in dirty and candidate not in active:
                            dependency = candidate
                            break
                if dependency is not None:
                    stack.append(dependency)
                    active.add(dependency)
                    continue
                stack.pop()
                active.remove(key)
                if key in dirty:
                    dirty.remove(key)
                    if solve(key):
                        changed = True

            if (not changed and len(self.summaries) == previous_contexts
                    and len(initializer_jobs) == previous_initializer_jobs):
                if initializing:
                    # Initialization only warms the ordinary fixed point;
                    # every base function and callback still runs afterward.
                    initializing = False
                    continue
                self.refresh_globals(globals_)
                effects = {}
                framework_bound = self.framework_bound(globals_)
                self.framework_values = framework_bound
                global_bound = {f'@global:{name}': globals_.value(name) for name in globals_}
                # Contextual effects belong to their calling invocation, not
                # an invented standalone/framework entry into a foreign scope.
                projections = [(self.tree, [(*key, fact) for key, fact in module.effects.items()])]
                for function in self.functions:
                    key = self.framework_summary_key(function)
                    scope_effects = (self.summaries[key].effects if isinstance(key, tuple)
                                     else solved[function][2])
                    projections.append((function, scope_effects))
                for scope, scope_effects in projections:
                    bound = global_bound
                    if scope is not self.tree and framework_bound.get(scope):
                        bound = {**global_bound, **framework_bound[scope]}
                    for kind, line, column, label, fact in scope_effects:
                        key = (kind, line, column, label)
                        if scope is not self.tree:
                            # Framework invocation is a separate entry point;
                            # summaries remain symbolic for ordinary callers.
                            fact = self.flow_class.substitute(fact, bound, _call_name(scope), budget=self.budget)
                        concrete = frozenset(trace for trace in fact if trace.parameter is None
                                             and not _safe_for(trace, key[0], key[3]))
                        if concrete:
                            effects[key] = join_facts(effects.get(key, CLEAN), concrete)
                problems = list(dict.fromkeys([*self.scope_errors, *self.failed_scopes.values()]))
                diagnostics = list(self.scope_diagnostics)
                for items in self.failed_scope_diagnostics.values():
                    diagnostics.extend(items)
                if self._escaping_namespace_factory():
                    reason = 'globals mapping factory stored in an object; analysis is incomplete'
                    problems.append(reason)
                    diagnostics.append(self.scope_diagnostic(self.tree, reason))
                if problems:
                    more = (f'; and {len(problems) - 8} more failed scopes'
                            if len(problems) > 8 else '')
                    raise AnalysisLimit('Python flow analysis is incomplete: '
                                        + '; '.join(problems[:8]) + more, effects=effects,
                                        components=_distinct_components(diagnostics))
                return effects


def _parse_source(path):
    """Decode Python source faithfully and make input failures explicit."""
    try:
        with tokenize.open(path) as source:
            text = source.read()
        return text, ast.parse(text, filename=str(path))
    except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError, LookupError) as exc:
        reason = f'{type(exc).__name__}: {exc}; analysis is incomplete'
        start = getattr(exc, 'lineno', None) or 1
        end = getattr(exc, 'end_lineno', None) or start
        raise AnalysisLimit(
            f'Cannot analyze Python source {path}: {reason}',
            components=({'file': str(path), 'symbol': '<module>',
                         'start_line': start, 'end_line': end, 'reason': reason},),
        ) from exc


def _sink_traces(effects):
    """Choose one concrete witness per process call, after domain filtering."""
    findings = {}
    for key, fact in effects.items():
        if not fact:
            continue
        trace = min(fact, key=lambda item: (len(item.path), item.path, item.source))
        site = key[:3] if key[0] == 'command' else key
        previous = findings.get(site)
        rank = (len(trace.path), trace.path, trace.source, key[3])
        if previous is None or rank < previous[0]:
            findings[site] = (rank, key, trace)
    return [(key, trace) for _rank, key, trace in sorted(
        findings.values(), key=lambda item: (item[1][1], item[1][2], item[1][0]))]


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
        self.journal = {}
        self.sources = []
        self.input_failures = []
        self.input_diagnostics = []
        self.failed_inputs = 0
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
                text, tree = _parse_source(path)
            except AnalysisLimit as exc:
                self.failed_inputs += 1
                self.input_diagnostics.extend(exc.components)
                if len(self.input_failures) < 3:
                    self.input_failures.append(str(exc))
                continue
            ast.increment_lineno(tree, offset)
            engine = _Analysis(tree, self)
            engine.line_offset = offset
            engine.source_path = path
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
        self.paths = {engine: path for path, _, engine, _ in self.sources}
        self.import_dependencies = {engine: self.dependencies(engine) for _, _, engine, _ in self.sources}
        self.owners = {function: engine for _, _, engine, _ in self.sources for function in engine.functions}
        self.module_references = {'@module:' + str(key) for key in self.namespaces}
        self.module_ref_map = {key: frozenset({key}) for key in self.module_references}
        # Only import-connected modules can exchange AST-backed callables.
        # Keep callbacks in both directions together, but do not make every
        # unrelated file scan their summaries or inherit their writer ordering.
        # Variable namespaces and framework entries remain module-local.
        for group in self.sharing_groups():
            owners = {function: engine for engine in group for function in engine.functions}
            for engine in group:
                engine.function_owners = owners
                engine.generator_peers = tuple(group)
            for name in ('summaries', 'defaults', 'default_references', 'default_bindings', 'parents', 'locals', 'closures',
                         'cell_owners', 'cell_locals', 'declared_globals',
                         'used_names', 'shadowed_globals', 'shadowed_global_values', 'active_globals',
                         'class_members', 'class_callables'):
                shared = {}
                for engine in group:
                    shared.update(getattr(engine, name))
                for engine in group:
                    setattr(engine, name, shared)
            generators = set().union(*(engine.generators for engine in group))
            for engine in group:
                engine.generators = generators

    def module_reference(self, engine):
        key = self.keys.get(engine)
        return '@module:' + str(key) if key is not None else None

    def import_key(self, engine, node, name):
        if isinstance(node, ast.ImportFrom) and node.level:
            key = self.keys.get(engine)
            if key is None:
                return None
            path = self.paths[engine]
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
        for node in engine.imports:
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
        adjacency = self.import_dependencies
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

    def sharing_groups(self):
        """Keep every modeled callable exchange in one metadata component.

        Imports can expose namespace descendants without an initialization
        dependency: ``import pkg`` permits ``pkg.child.helper``. An unaliased
        ``import pkg.first`` also exposes siblings through ``pkg``. Include
        those potential exchanges here, without adding false import cycles
        to the directed graph used for initialization and opaque fallbacks.
        """
        parents = {engine: engine for engine in self.import_dependencies}
        sizes = {engine: 1 for engine in parents}

        def representative(engine):
            while parents[engine] is not engine:
                parents[engine] = parents[parents[engine]]
                engine = parents[engine]
            return engine

        def connect(left, right):
            left, right = representative(left), representative(right)
            if left is right:
                return
            if sizes[left] < sizes[right]:
                left, right = right, left
            parents[right] = left
            sizes[left] += sizes[right]

        # Index each namespace once. Repeated imports of a broad package
        # should not repeatedly walk all its selected descendants.
        namespace_members = defaultdict(list)
        for engine, key in self.keys.items():
            for prefix in (key, *key.parents):
                if prefix in self.namespaces:
                    namespace_members[prefix].append(engine)
        connected_namespaces = set()

        def expose(engine, key):
            members = namespace_members.get(key, ())
            if not members:
                return
            if key not in connected_namespaces:
                for member in members[1:]:
                    connect(members[0], member)
                connected_namespaces.add(key)
            connect(engine, members[0])

        for engine, dependencies in self.import_dependencies.items():
            for dependency in dependencies:
                connect(engine, dependency)
            for node in engine.imports:
                if isinstance(node, ast.ImportFrom):
                    key = self.import_key(engine, node, node.module or '')
                    if key in self.namespaces:
                        for alias in node.names:
                            if alias.name != '*':
                                expose(engine, key / alias.name)
                else:
                    for alias in node.names:
                        key = self.import_key(engine, node, alias.name)
                        if key in self.namespaces:
                            exposed = key if alias.asname else self.import_key(
                                engine, node, alias.name.split('.')[0])
                            expose(engine, exposed)
        groups = defaultdict(list)
        for engine in parents:
            groups[representative(engine)].append(engine)
        yield from groups.values()

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
                    # functions. Only the unshadowed builtin staticmethod and
                    # classmethod descriptors are safe while peers initialize.
                    shadowed = engine.global_names | _local_names(node)
                    if (engine.plain_class(node, _State(bindings={name: None for name in engine.global_names}))
                            and all(isinstance(decorator, ast.Name) and decorator.id in {'staticmethod', 'classmethod'}
                                    and decorator.id not in shadowed
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
            engine.refresh_globals(engine.flow_class(engine, engine.tree).block(engine.tree.body, _State()) or _State())
        self.ready.update(component)
        self.solving = set(component)
        try:
            while True:
                summaries = component[0].summaries.copy()
                effects = {}
                try:
                    for engine in component:
                        for key, fact in engine.analyze().items():
                            effects[key] = join_facts(effects.get(key, CLEAN), fact)
                except AnalysisLimit as exc:
                    for key, fact in effects.items():
                        exc.effects[key] = join_facts(exc.effects.get(key, CLEAN), fact)
                    raise
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
        failures, failed_components = [], 0
        diagnostics = list(self.input_diagnostics)
        paths = self.paths
        for component in self.components():
            self.journal.clear()
            completed = {}
            try:
                cyclic = len(component) > 1 or component[0] in self.import_dependencies[component[0]]
                if cyclic and self.deferred_cycle(component):
                    completed = self.analyze_cycle(component)
                else:
                    if cyclic:
                        # Opaque imports are confined to the actual cycle.
                        for engine in component:
                            engine.project = None
                    completed = {}
                    for engine in component:
                        for key, fact in engine.analyze().items():
                            completed[key] = join_facts(completed.get(key, CLEAN), fact)
                        self.ready.add(engine)
                for key, fact in completed.items():
                    effects[key] = join_facts(effects.get(key, CLEAN), fact)
            except AnalysisLimit as exc:
                if exc.components:
                    diagnostics.extend(exc.components)
                else:
                    diagnostics.extend(engine.scope_diagnostic(engine.tree, str(exc)) for engine in component)
                for key, fact in completed.items():
                    effects[key] = join_facts(effects.get(key, CLEAN), fact)
                for key, fact in exc.effects.items():
                    effects[key] = join_facts(effects.get(key, CLEAN), fact)
                # A failed callback solve can also have written a foreign
                # context in the shared table. Never let later modules reuse
                # that provisional bottom summary as a completed result.
                for table, key, previous in self.journal.values():
                    if previous is _MISSING:
                        table.pop(key, None)
                    else:
                        table[key] = previous
                self.ready.difference_update(component)
                failed_components += 1
                if len(failures) < 3:
                    names = ', '.join(str(paths[engine]) for engine in component[:3])
                    failures.append(f'{names}: {exc}')
            finally:
                self.journal.clear()
        starts = [offset for _, _, _, offset in self.sources]
        indexes = {path: build_index(text, lang='python') for path, text, _, _ in self.sources}
        for (kind, line, column, label), trace in _sink_traces(effects):
            path, _, _, offset = self.sources[bisect_right(starts, line - 1) - 1]
            line -= offset
            rule = f'py.taint.{kind}'
            if indexes[path].is_suppressed(line, rule) or indexes[path].is_suppressed(line, f'python.taint.{kind}'):
                continue
            yield path, rule, line, column, ' -> '.join((*trace.path, label))
        problems = []
        if self.failed_inputs:
            omitted = (f'; and {self.failed_inputs - len(self.input_failures)} more failed inputs'
                       if self.failed_inputs > len(self.input_failures) else '')
            problems.append(f'{self.failed_inputs} input(s): '
                            + '; '.join(self.input_failures) + omitted)
        if failed_components:
            omitted = (f'; and {failed_components - len(failures)} more failed components'
                       if failed_components > len(failures) else '')
            problems.append(f'{failed_components} component(s): ' + '; '.join(failures) + omitted)
        if problems:
            # Foreign callbacks can be reached from several import components.
            # Report each source failure once without truncating the payload.
            raise AnalysisLimit('Python taint analysis is incomplete in ' + '; '.join(problems),
                                components=_distinct_components(diagnostics))


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
    incomplete = None
    try:
        for path, rule, line, _col, description in _Project(iter_files(ROOT), BASE_DIR).findings():
            bucket = issues[rule]
            bucket['count'] += 1
            if len(bucket['samples']) < 3:
                bucket['samples'].append(f'{path.relative_to(BASE_DIR)}:{line} {description}')
    except AnalysisLimit as exc:
        incomplete = str(exc)
    for rule_id, data in issues.items():
        samples = ','.join(data['samples'])
        print(f"{rule_id}\t{data['count']}\t{samples}")
    if incomplete is not None:
        print(incomplete, file=sys.stderr)
        return 2
    return 0


_SEVERITY = {
    "xss": "critical",
    "sql": "critical",
    "command": "critical",
    "eval": "critical",
    "ssrf": "critical",
}

_MESSAGE = {
    "xss": "Unsanitized request data reaches HTML/response sinks",
    "sql": "User input flows into SQL execute() without parameters",
    "command": "User input reaches subprocess/os.system",
    "eval": "User input flows into eval/exec",
    "ssrf": "User input controls an outbound HTTP request URL (possible SSRF)",
}


def scan_file_findings(path: Path):
    """Yield each reachable source-to-sink flow once at its sink location."""
    text, tree = _parse_source(path)
    suppressions = build_index(text, lang='python')
    engine = _Analysis(tree)
    engine.source_path = path
    incomplete = None
    try:
        effects = engine.analyze()
    except AnalysisLimit as exc:
        effects, incomplete = exc.effects, exc
    for (kind, line, column, label), trace in _sink_traces(effects):
        rule = f'py.taint.{kind}'
        if suppressions.is_suppressed(line, rule) or suppressions.is_suppressed(line, f'python.taint.{kind}'):
            continue
        path_desc = ' -> '.join((*trace.path, label))
        yield rule, line, column, path_desc
    if incomplete is not None:
        raise incomplete


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
