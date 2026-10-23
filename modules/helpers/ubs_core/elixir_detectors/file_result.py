"""Track selected File error results through Elixir bindings and local calls.

Non-bang File operations return either a success value or an error tuple. A
plain call or an unused assignment can lose that failure just as easily as an
explicit ``{:error, _}`` pattern. Keep a separate obligation for each call:
returning the result transfers it, while a status match/branch observes it.
This is deliberately a bounded File contract, not a generic unused-value rule.
"""
from __future__ import annotations

from pathlib import Path

from ubs_core.analyzers.lifecycle_elixir import ElixirLifecycleEngine, LifecycleParser
from ubs_core.analyzers.taint_elixir_traversal import (
    ElixirEngine, ElixirSyntaxError, Expr, FlowState, Parser, Value,
)
from ubs_core.elixir_detectors._common import EXTS, elixir_files
from ubs_core.suppression import build_index
from ubs_core.taint_flow import Budget


RULE_ID = "ex.error.unhandled-file-result"
CATEGORY = 2
TITLE = "File operation failure result is not handled"
SEVERITY = "warning"
DESCRIPTION = "Match the result, return it to the caller, or use the raising File API when failure must abort."

# Elixir File's documented non-bang contracts. The boolean says whether success
# is {:ok, value}, rather than :ok. In particular File.exists?/regular?/dir?
# return booleans, and bang functions raise, so they carry no such obligation.
FILE_RESULTS = {
    "read": ({1}, True), "write": ({2, 3}, False),
    "copy": ({2, 3}, True), "cp": ({2, 3}, False),
    "rename": ({2}, False), "rm": ({1}, False),
    "mkdir": ({1}, False), "mkdir_p": ({1}, False),
    "stat": ({1, 2}, True), "ls": ({0, 1}, True),
}
_RESULT = "file-result.pending"


class FileResultEngine(ElixirLifecycleEngine):
    """Reuse native control flow without introducing file/task handle checks."""

    def __init__(self, path: Path, text: str, budget: Budget | None = None):
        super().__init__(path, text, budget, families=frozenset())
        self.origins: dict[tuple, tuple[int, int, str]] = {}
        self.unhandled: dict[tuple[int, int], str] = {}
        self.serial = 0
        self.file_import_scopes: dict[str, list[tuple[int, frozenset]]] = {}
        self.attribute_values: set[int] = set()
        self.task_depth = 0

    def register_block(self, block, owner=''):
        # The shared frontend records imported names for taint refusal. Result
        # contracts need the selected arity as well, and a later import must not
        # retroactively change the binding of an earlier function definition.
        aliases, selected = {}, set()
        scopes = [(-1, frozenset())]
        for expr in block.args:
            if expr.kind == 'set_attribute':
                self.attribute_values.add(id(expr.args[0]))
            if expr.kind != 'call':
                continue
            directive = Parser.name(expr.args[0])
            if directive == 'alias' and len(expr.args) >= 2:
                target = Parser.name(expr.args[1])
                short = target.split('.')[-1]
                for option in expr.args[2:]:
                    if option.kind == 'pair' and option.value == 'as':
                        short = Parser.name(option.args[0])
                aliases[short] = target
            if directive != 'import' or len(expr.args) < 2:
                continue
            target = Parser.name(expr.args[1])
            first, *rest = target.split('.')
            target = '.'.join((aliases.get(first, first), *rest)).removeprefix('Elixir.')
            imported = {(name, arity) for name, (arities, _) in FILE_RESULTS.items() for arity in arities}
            for option in expr.args[2:]:
                if option.kind != 'pair' or option.value not in {'only', 'except'}:
                    continue
                members = option.args[0]
                if members.kind != 'list' or any(item.kind != 'pair' or item.args[0].kind != 'number' for item in members.args):
                    raise ElixirSyntaxError(f'Unresolved File import at line {expr.token.line}; analysis is incomplete')
                pairs = {(item.value, int(item.args[0].value)) for item in members.args}
                imported = imported & pairs if option.value == 'only' else imported - pairs
            selected = imported if target == 'File' else selected - imported
            scopes.append((expr.token.offset, frozenset(selected)))
        self.file_import_scopes[owner] = scopes
        return super().register_block(block, owner)

    def imported_file_call(self, expr, name, arity):
        offset = self.function_scope.token.offset if self.function_scope is not None else expr.token.offset
        scopes = self.file_import_scopes.get(self.owner, ())
        selected = next((members for start, members in reversed(scopes) if start < offset), frozenset())
        return (name, arity) in selected

    def pending(self, state):
        return {key[1:] for key in state.checks if key and key[0] == _RESULT}

    def result_references(self, value):
        if value.kind == "file_result":
            return {value.identity}
        if value.kind == "callback":
            closure = self.closures.get(value.identity)
            return set().union(*(self.result_references(item) for _, item in closure[1])) if closure else set()
        if value.kind == "map":
            return set().union(*(self.result_references(item) for _, item in value.items))
        if value.kind in {"tuple", "list", "pair", "map_pair", "set"}:
            return set().union(*(self.result_references(item) for item in value.items))
        return set()

    def observed(self, state, identities):
        after = state.copy()
        for identity in identities:
            after.checks.pop((_RESULT, *identity), None)
        return after

    def observe(self, state, value, inherited=frozenset(), transfer=True):
        # An explicit failing match/raise propagates failure instead of claiming
        # successful completion. Handle cleanup is a separate analyzer's job.
        if self.terminated(state):
            return
        returned = self.result_references(value) if transfer else set()
        if self.has_callback(value) and returned & self.pending(state):
            raise ElixirSyntaxError("Deferred Elixir File-result ownership is unresolved; analysis is incomplete")
        for identity in self.pending(state) - set(inherited) - returned:
            line, col, call = self.origins[identity]
            self.unhandled[line, col] = call

    def analyze(self):
        pending, names = [self.tokens], set()
        while pending:
            for token in pending.pop():
                if token.kind == "id":
                    names.add(token.text)
                pending.extend(token.interpolations)
        if "File" not in names or not names.intersection(FILE_RESULTS):
            return self.unhandled
        program = LifecycleParser(self.tokens, self.budget).block()
        self.register_block(program)
        for key, clauses in tuple(self.functions.items()):
            self.owner, self.context = key[0], ("entry", key[1], key[2])
            for function in clauses:
                if function.public and key[2] == len(function.parameters):
                    self.invoke(key, self.entry_arguments(function), FlowState(),
                                Expr("name", function.token, function.name))
        return self.unhandled

    def invoke(self, key, args, state, expr):
        inherited = self.pending(state)
        outcomes = ElixirEngine.invoke(self, key, args, state, expr)
        for after, value in outcomes:
            self.observe(after, value, inherited)
        return outcomes

    def invoke_callback(self, expr, callback, args, state):
        inherited = self.pending(state)
        outcomes = ElixirEngine.invoke_callback(self, expr, callback, args, state)
        for after, value in outcomes:
            self.observe(after, value, inherited)
            if self.task_depth and self.result_references(value) & self.pending(after):
                raise ElixirSyntaxError('File-result transfer through an asynchronous Task is unresolved; analysis is incomplete')
        return outcomes

    def task_body(self, expr, module, args, state):
        self.task_depth += 1
        try:
            return super().task_body(expr, module, args, state)
        finally:
            self.task_depth -= 1

    def match(self, pattern, value, state, bound=None):
        if value.kind != "file_result" or pattern.kind == "name":
            return super().match(pattern, value, state, bound)
        if pattern.kind == "binary" and pattern.value == "=":
            return super().match(pattern, value, state, bound)
        status_pattern = (pattern.kind == "atom" and pattern.value == "ok") or (
            pattern.kind == "tuple" and pattern.args and pattern.args[0].kind == "atom"
            and pattern.args[0].value in {"ok", "error"})
        if not status_pattern:
            raise ElixirSyntaxError(f"Unresolved File-result pattern at line {pattern.token.line}; analysis is incomplete")
        matches, failed = [], False
        for outcome in value.items:
            bindings = dict(bound or {})
            selected, can_fail = super().match(pattern, outcome, state, bindings)
            matches.extend(self.observed(item, {value.identity}) for item in selected)
            if selected and bound is not None:
                bound.update(bindings)
            failed |= can_fail
        return [item for item, _ in self.outcomes((item, Value()) for item in matches)], failed

    def refine(self, predicate, state, truth):
        if predicate.kind == "test" and predicate.test[0] in {"==", "===", "!=", "!=="}:
            first, second = predicate.test[1:]
            checked = set()
            for result, status in ((first, second), (second, first)):
                if (result.kind == "file_result" and result.items[0].kind == "atom"
                        and status.kind == "atom" and status.literal == "ok"):
                    checked.add(result.identity)
            state = self.observed(state, checked)
        return super().refine(predicate, state, truth)

    def _refine(self, predicate, state, truth):
        if predicate.kind == "file_result":
            # Both :ok and {:error, reason} are truthy. `if result` is not an
            # error check and cannot discharge the obligation.
            return [state.copy()] if truth else []
        return super()._refine(predicate, state, truth)

    def evaluate(self, expr, state):
        if expr.kind == 'member' and expr.value == 'ls':
            module = self.resolve_module(Parser.name(expr.args[0]))
            if module == 'File' and module not in self.attributes:
                results = self.builtin(expr, module, 'ls', (), state, True)
            else:
                results = super().evaluate(expr, state)
        else:
            results = super().evaluate(expr, state)
        # Attribute initialization discards its flow state in the shared
        # frontend. Refuse pending results here, before a later attribute
        # redefinition could hide the unresolved compile-time obligation.
        if id(expr) in self.attribute_values and any(self.pending(after) for after, _ in results):
            raise ElixirSyntaxError("File-result storage in a module attribute is unresolved; analysis is incomplete")
        return results

    def builtin(self, expr, module, name, args, state, qualified):
        selected_module = module if qualified else 'File' if self.imported_file_call(expr, name, len(args)) else ''
        if selected_module == "File" and selected_module not in self.attributes and name in FILE_RESULTS:
            arities, tuple_success = FILE_RESULTS[name]
            if len(args) not in arities:
                raise ElixirSyntaxError(f"Unsupported File.{name} arity at line {expr.token.line}; analysis is incomplete")
            if any(self.has_callback(arg) for arg in args):
                raise ElixirSyntaxError(f"File.{name} callback invocation is unresolved at line {expr.token.line}; analysis is incomplete")
            self.serial += 1
            identity = (*self.identity(expr), "result", self.serial)
            self.origins[identity] = (expr.token.line, expr.token.col, "File." + name)
            after = state.copy()
            after.checks[(_RESULT, *identity)] = frozenset({"pending"})
            success = Value("tuple", items=(Value("atom", "ok"), Value("parameter"))) if tuple_success else Value("atom", "ok")
            failure = Value("tuple", items=(Value("atom", "error"), Value("parameter")))
            # Split only when a result is matched. Eager success/error paths for
            # N independent writes would manufacture 2**N analysis states.
            return [(after, Value("file_result", identity=identity, items=(success, failure)))]
        canonical = f"{module}.{name}" if qualified else name
        references = set().union(*(self.result_references(arg) for arg in args))
        if canonical == "IO.inspect" and args:
            return [(state, args[0])]
        if canonical in {"raise", "throw", "exit", "Kernel.raise", "Kernel.throw", "Kernel.exit"}:
            return [self.terminate(state, name, args[0] if args else Value())]
        if canonical in {"Enum.each", "Enum.map", "Enum.reduce", "then", "Kernel.then", "tap", "Kernel.tap",
                         "Map.get", "Map.fetch", "Map.fetch!", "Keyword.get", "Keyword.fetch", "Keyword.fetch!",
                         "List.first", "hd", "Kernel.hd", "elem", "Kernel.elem", "get_in"}:
            return ElixirEngine.builtin(self, expr, module, name, args, state, qualified)
        if references & self.pending(state):
            raise ElixirSyntaxError(f"Unresolved File-result consumer {canonical} at line {expr.token.line}; analysis is incomplete")
        return super().builtin(expr, module, name, args, state, qualified)


def scan_file_findings(path: Path, budget: Budget | None = None):
    text = path.read_text(encoding="utf-8")
    engine = FileResultEngine(path, text, budget)
    suppressions = build_index(text, lang="elixir")
    incomplete = None
    try:
        engine.analyze()
    except ValueError as exc:
        incomplete = exc
    for (line, col), call in sorted(engine.unhandled.items()):
        if not suppressions.is_suppressed(line, RULE_ID):
            yield line, col, call
    if incomplete is not None:
        raise incomplete


def find(files):
    errors = []
    for path in elixir_files(files, EXTS):
        try:
            for line, col, call in scan_file_findings(path):
                yield str(path), line, col, call
        except ValueError as exc:
            errors.append(f"{path}: {exc}")
    if errors:
        raise ElixirSyntaxError("; ".join(errors))
