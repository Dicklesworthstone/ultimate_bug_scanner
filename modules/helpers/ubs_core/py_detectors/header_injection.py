"""Scoped HTTP response header flow, with body-proven CR/LF safety.

The shared Python fixed point supplies assignments, branches, local helpers,
framework inputs, aliases and exceptional exits. This adapter adds header
sinks and separate CR/LF proofs: a reassuring function name is never proof.
Only imported encoder identities or an analyzed replacement/rejection body
can establish safety. Unknown transformations and namespace writes revoke it.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from string import Formatter
from typing import Iterable, Sequence

from ubs_core.analyzers import taint_py as flow
from ubs_core.suppression import SourceSuppressions

RULE_ID = "py.security.header-injection"
CATEGORY = 7
TITLE = "Request-controlled value reaches HTTP response header"
SEVERITY = "critical"
DESCRIPTION = ("Reject CR/LF, use fixed header names, and encode filenames with "
               "framework-safe helpers before setting headers")

HEADER_DICT_KEYWORDS = {'headers', 'response_headers'}
FILENAME_KEYWORDS = {'download_name', 'attachment_filename', 'filename', 'as_attachment_filename'}
HEADER_METHODS = {'add', 'set', 'setdefault', 'append', 'update'}
RESPONSE_FACTORIES = {
    'Response', 'flask.Response', 'make_response', 'flask.make_response',
    'HttpResponse', 'django.http.HttpResponse',
    'JsonResponse', 'django.http.JsonResponse',
    'StreamingHttpResponse', 'django.http.StreamingHttpResponse',
    'HTMLResponse', 'PlainTextResponse', 'JSONResponse',
    'starlette.responses.HTMLResponse', 'starlette.responses.PlainTextResponse',
    'starlette.responses.JSONResponse', 'fastapi.responses.HTMLResponse',
    'fastapi.responses.PlainTextResponse', 'fastapi.responses.JSONResponse',
    'FileResponse', 'django.http.FileResponse',
    'RedirectResponse', 'starlette.responses.RedirectResponse',
}
FILE_RESPONSE_FACTORIES = {
    'send_file', 'flask.send_file', 'FileResponse', 'django.http.FileResponse',
    'starlette.responses.FileResponse', 'fastapi.responses.FileResponse',
}
_ENCODERS = {'urllib.parse.quote', 'urllib.parse.quote_plus', 'werkzeug.utils.secure_filename'}
_MODULES = {'urllib', 'urllib.parse', 'werkzeug', 'werkzeug.utils'}
_IMPORT = '@header-import:'
_MODULE_REF = '@header-module:'
_HEADER_OBJECT = '@header-object:headers'
_RESPONSE_OBJECT = '@header-object:response'
_CR, _LF, _RESET = 'header:cr', 'header:lf', 'header:reset'
_CONTROLS = frozenset({_CR, _LF})
_CHAR_PERCENT = re.compile(r'%(?:\([^)]*\))?[#0\- +]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[hlL]?c')
# A cutoff is an explicit incomplete detector result, never a clean verdict.
MAX_FLOW_STEPS = 250_000


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ''


def _source_line(lines, line_no):
    return lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ''


def _header_target(target):
    if not isinstance(target, ast.Subscript):
        return False
    owner = _call_name(target.value)
    leaf = owner.rsplit('.', 1)[-1].lower()
    return (leaf in HEADER_DICT_KEYWORDS
            or leaf in {'resp', 'response', 'httpresponse'} or leaf.endswith('_response'))


def _has_sink(tree):
    """Cheap structural filter before allocating a function-summary engine.

    Include headers= and imported response factories so aliases still reach
    the semantic pass. A filename= keyword alone is not a response sink (AST
    parsers and file utilities use it too), nor is text in strings/comments.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(alias.name in RESPONSE_FACTORIES | FILE_RESPONSE_FACTORIES
                                                   for alias in node.names):
            return True
        if isinstance(node, ast.Attribute) and node.attr in HEADER_DICT_KEYWORDS:
            return True
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store) and _header_target(node):
            return True
        if isinstance(node, ast.Call):
            if _call_name(node.func).rsplit('.', 1)[-1] in RESPONSE_FACTORIES | FILE_RESPONSE_FACTORIES:
                return True
            if any(k.arg in HEADER_DICT_KEYWORDS for k in node.keywords):
                return True
            if (isinstance(node.func, ast.Attribute) and node.func.attr in HEADER_METHODS
                    and _call_name(node.func.value).rsplit('.', 1)[-1] in HEADER_DICT_KEYWORDS):
                return True
    return False


def _safe(trace):
    return _CONTROLS <= trace.sanitizers


def _prove(fact, controls=_CONTROLS):
    return frozenset(flow.TaintTrace(t.source, t.parameter, t.sanitizers | controls, t.path) for t in fact)


def _revoke(fact):
    return frozenset(flow.TaintTrace(t.source, t.parameter,
                                    (t.sanitizers - _CONTROLS) | {_RESET}, t.path) for t in fact)


def _import_name(binding):
    if isinstance(binding, flow._BoundCallable):
        binding = binding.name
    return binding[len(_IMPORT):] if isinstance(binding, str) and binding.startswith(_IMPORT) else None


def _module_refs(binding):
    return frozenset(_MODULE_REF + name for choice in flow._binding_choices(binding)
                     if (name := _import_name(choice)) in _MODULES)


class _HeaderFlow(flow._Flow):
    @staticmethod
    def substitute_trace(trace, actual, call_name):
        # The call-local cache uses this domain's transformation. Revocation
        # must happen before new proofs, for both cached and direct expansion.
        if trace.parameter is None:
            return frozenset({trace})
        if _RESET in trace.sanitizers:
            actual = _revoke(actual)
        for sanitizer in trace.sanitizers - {_RESET}:
            actual = flow._sanitize(actual, sanitizer)
        steps = trace.path[1:] if trace.parameter.startswith('@') else trace.path
        return flow._advance(actual, call_name, *steps)

    def effect(self, kind, node, label, fact):
        if kind == 'header' and fact:
            # Keep proofs until caller substitution: an earlier operation in
            # a helper can revoke an encoded argument supplied by its caller.
            key = (kind, node.lineno, node.col_offset + 1, label)
            self.effects[key] = flow.join_facts(self.effects.get(key, flow.CLEAN), fact)

    def _lookup_refs(self, references, key):
        if isinstance(key, str) and key.startswith(_MODULE_REF):
            return frozenset({key})
        return super()._lookup_refs(references, key)

    def mutate(self, references, fact, state):
        super().mutate(references, fact, state)
        module_refs = frozenset(ref for ref in references
                                if isinstance(ref, str) and ref.startswith(_MODULE_REF))
        if not module_refs:
            return
        # A helper can mutate a global encoder even when its caller never
        # otherwise reads that global. Carry the invalidation into the next
        # helper's context instead of resurrecting the module's base binding.
        names = set(state.bindings) | set(self.engine.globals.bindings)
        local = self.engine.locals.get(self.scope, set())
        changed_globals = set(self.context_globals)
        for name in names:
            binding = state.bindings.get(name, self.engine.globals.bindings.get(name))
            refs = _module_refs(binding) | state.references.get(name, flow.NO_REFERENCES)
            if not refs & module_refs:
                continue
            choices = [None if _import_name(choice) in _MODULES else choice
                       for choice in flow._binding_choices(binding)]
            state.bindings[name] = flow._join_bindings(*choices)
            if name not in local and name in self.engine.global_symbols:
                value, global_refs, _binding = self.engine.global_symbols[name]
                state.setdefault(name, value)
                state.references[name] = refs | global_refs
                changed_globals.add(name)
        self.context_globals = tuple(sorted(changed_globals))

    def statement(self, node, state):
        if isinstance(node, ast.ImportFrom) and any(alias.name == '*' for alias in node.names):
            # A star import can replace any current callable, including a
            # previously captured encoder. Only a later explicit import can
            # establish a new identity.
            for name, binding in tuple(state.bindings.items()):
                state.bindings[name] = flow._join_bindings(*(
                    None if _import_name(choice) else choice for choice in flow._binding_choices(binding)))
            return state
        result = super().statement(node, state)
        if result is not None and isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or alias.name.split('.')[0]
                name = (f'{node.module}.{alias.name}' if isinstance(node, ast.ImportFrom)
                        else alias.name if alias.asname else local)
                if name in _MODULES | _ENCODERS:
                    refs = frozenset({_MODULE_REF + name}) if name in _MODULES else flow.NO_REFERENCES
                    owner = name.rsplit('.', 1)[0]
                    invalid = (_MODULE_REF + name in state.mutated or _MODULE_REF + owner in state.mutated)
                    result.bindings[local] = None if invalid else _IMPORT + name
                    result.references[local] = refs
        return result

    def source(self, node, state, candidate=None):
        fact = super().source(node, state, candidate)
        name = candidate or _call_name(node)
        if isinstance(node, ast.Call) and name.rstrip('(') in {'sys.stdin.read', 'sys.stdin.readline'}:
            return flow.join_facts(fact, frozenset({flow.TaintTrace(name, path=(name,))}))
        return fact

    def expr(self, node, state):
        if node is None or not state.reachable:
            return flow.CLEAN
        self.engine.steps += 1
        if self.engine.steps > MAX_FLOW_STEPS:
            raise RuntimeError(f'header flow exceeded {MAX_FLOW_STEPS} evaluation steps')
        fact = super().expr(node, state)
        binding = self.expression_bindings.get(node)
        if isinstance(node, ast.Name):
            refs = self.expression_references.get(node, flow.NO_REFERENCES) | _module_refs(binding)
            self.expression_references[node] = refs
            if refs & state.mutated:
                binding = flow._join_bindings(*(
                    None if _import_name(choice) in _MODULES else choice
                    for choice in flow._binding_choices(binding)))
        elif isinstance(node, ast.Attribute):
            parents = flow._binding_choices(self.expression_bindings.get(node.value))
            choices = []
            refs = self.expression_references.get(node.value, flow.NO_REFERENCES)
            for parent in parents:
                imported = _import_name(parent)
                if imported is not None:
                    name = f'{imported}.{node.attr}'
                    choices.append(None if refs & state.mutated else _IMPORT + name)
                else:
                    # Core spelling fallbacks are useful for sources/sinks,
                    # but cannot recreate a shadowed imported encoder.
                    candidates = flow._binding_choices(binding)
                    choices.extend(None if _import_name(c) else c for c in candidates)
            binding = flow._join_bindings(*choices)
            module_refs = _module_refs(binding)
            if module_refs:
                self.expression_references[node] = refs | module_refs
            elif all(_import_name(choice) in _ENCODERS for choice in flow._binding_choices(binding)):
                # Reading the function captures its current identity. A later
                # write to module.quote must not change saved = module.quote.
                self.expression_references[node] = flow.NO_REFERENCES
        self.expression_bindings[node] = binding
        if isinstance(node, ast.Attribute) and node.attr in HEADER_DICT_KEYWORDS:
            self.expression_bindings[node] = _HEADER_OBJECT
        return fact

    def _literal(self, node):
        binding = self.expression_bindings.get(node)
        if isinstance(binding, flow._LiteralString):
            return binding.value
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    def _harmless(self, node):
        if isinstance(node, ast.FormattedValue):
            return self._plain_format(node.format_spec) and self._harmless(node.value)
        text = self._literal(node)
        if text is not None:
            return '\r' not in text and '\n' not in text
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, bool, type(None))):
            return True
        fact = self.expression_facts.get(node, flow.CLEAN)
        return bool(fact) and all(_safe(trace) for trace in fact)

    @staticmethod
    def _plain_format(spec):
        if spec is None:
            return True
        if isinstance(spec, ast.JoinedStr) and all(isinstance(v, ast.Constant) and isinstance(v.value, str)
                                                  for v in spec.values):
            text = ''.join(v.value for v in spec.values)
            return '\r' not in text and '\n' not in text and not text.endswith('c')
        return False

    @staticmethod
    def _plain_template(template):
        try:
            for literal, field, spec, _conversion in Formatter().parse(template):
                if ('\r' in literal or '\n' in literal or field and ('.' in field or '[' in field)
                        or spec and ('{' in spec or '}' in spec or '\r' in spec or '\n' in spec
                                     or spec.endswith('c'))):
                    return False
        except ValueError:
            return False
        return True

    def _composition(self, nodes, fact):
        # One symbolic varying operand plus fixed safe text preserves an
        # incoming caller proof. Multiple unproved components, including a
        # clean-but-unknown chr/format result, cannot certify the final string.
        varying = [node for node in nodes if not self._harmless(node)]
        if not varying:
            return fact
        if len(varying) == 1 and self.expression_facts.get(varying[0], flow.CLEAN):
            others = [node for node in nodes if node is not varying[0]]
            if all(self._harmless(node) for node in others):
                return fact
        return _revoke(fact)

    def expression(self, node, state):
        fact = super().expression(node, state)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            # Aggregate provenance is field-insensitive. An encoded member
            # does not prove the value of another selected field (which may
            # contain CR/LF literals or arbitrary property output). Method
            # invocation separately retains the receiver's original fact.
            return _revoke(fact)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                return self._composition([node.left, node.right], fact)
            if isinstance(node.op, ast.Mod):
                template = self._literal(node.left)
                if template is None or _CHAR_PERCENT.search(template):
                    return _revoke(fact)
                parts = node.right.elts if isinstance(node.right, (ast.Tuple, ast.List)) else [node.right]
                return self._composition([node.left, *parts], fact)
            return _revoke(fact)
        if isinstance(node, ast.JoinedStr):
            return self._composition(node.values, fact)
        if isinstance(node, ast.FormattedValue) and node.format_spec is not None:
            return fact if self._plain_format(node.format_spec) else _revoke(fact)
        return fact

    def assign(self, target, fact, state, value=None, *, target_references=None):
        if isinstance(target, ast.Subscript):
            if target_references is None:
                self.expr(target.value, state)
                target_references = self.expression_references.get(target.value, flow.NO_REFERENCES)
                key_fact = self.expr(target.slice, state)
            else:
                key_fact = self.expression_facts.get(target.slice, flow.CLEAN)
            owner = self.expression_bindings.get(target.value)
            if _header_target(target) or any(choice in {_HEADER_OBJECT, _RESPONSE_OBJECT}
                                              for choice in flow._binding_choices(owner)):
                self.effect('header', target, 'response header assignment', flow.join_facts(fact, key_fact))
        super().assign(target, fact, state, value, target_references=target_references)

    def refine_url_guard(self, test, state, truth):
        # The shared branch transfer evaluates the complete test first. If a
        # later operand can rebind a checked value, its earlier comparison
        # must not validate that replacement. Only pure membership predicates
        # establish a proof at this refinement point.
        if any(isinstance(node, (ast.NamedExpr, ast.Call, ast.Await, ast.Yield, ast.YieldFrom,
                                 ast.Attribute, ast.Subscript)) for node in ast.walk(test)):
            return
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.refine_url_guard(test.operand, state, not truth)
        if isinstance(test, ast.BoolOp) and ((isinstance(test.op, ast.And) and truth)
                                           or (isinstance(test.op, ast.Or) and not truth)):
            for value in test.values:
                self.refine_url_guard(value, state, truth)
        if (isinstance(test, ast.Compare) and len(test.ops) == 1
                and isinstance(test.comparators[0], ast.Name)
                and isinstance(test.ops[0], (ast.In, ast.NotIn))):
            absent = truth if isinstance(test.ops[0], ast.NotIn) else not truth
            text = self._literal(test.left)
            if absent and text in {'\r', '\n'}:
                name = test.comparators[0].id
                state[name] = _prove(state.value(name), frozenset({_CR if text == '\r' else _LF}))
                # String values are snapshots. Re-reading the symbolic heap
                # must not add the unrefined copy back to the proved value.
                state.references[name] = flow.NO_REFERENCES

    def invoke(self, node, state, callee, inputs, *, resumed=None):
        target = callee.binding
        name = target.name if isinstance(target, flow._BoundCallable) else target if isinstance(target, str) else callee.fallback_name
        name = name or ''
        short = node.func.attr if isinstance(node.func, ast.Attribute) else name.rsplit('.', 1)[-1]
        args, keywords, keyword_nodes = inputs.arguments, inputs.keywords, inputs.keyword_nodes
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        receiver_name = _call_name(receiver).rsplit('.', 1)[-1]
        sink = flow.CLEAN
        if short in HEADER_METHODS and (receiver_name in HEADER_DICT_KEYWORDS
                                       or name.startswith(_HEADER_OBJECT + '.')):
            sink = flow.join_facts(*args, *keywords.values())
        if name in RESPONSE_FACTORIES or short in RESPONSE_FACTORIES:
            sink = flow.join_facts(sink, *(keywords.get(key, flow.CLEAN) for key in HEADER_DICT_KEYWORDS))
        if name in FILE_RESPONSE_FACTORIES or short in FILE_RESPONSE_FACTORIES:
            sink = flow.join_facts(sink, *(keywords.get(key, flow.CLEAN) for key in FILENAME_KEYWORDS))
        self.effect('header', node, 'response header call', sink)
        local = isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                                    flow._BoundClassMethod))
        if not local:
            for expression in (*node.args, *keyword_nodes.values()):
                if _module_refs(self.expression_bindings.get(expression)):
                    self.mutate(self.expression_references.get(expression, flow.NO_REFERENCES), flow.CLEAN, state)
        result = super().invoke(node, state, callee, inputs, resumed=resumed)
        if local:
            return result
        if name in RESPONSE_FACTORIES or short in RESPONSE_FACTORIES:
            self.expression_bindings[node] = _RESPONSE_OBJECT
        imported = _import_name(target)
        if imported == 'werkzeug.utils.secure_filename':
            return _prove(result)
        if imported in {'urllib.parse.quote', 'urllib.parse.quote_plus'}:
            safe_node = node.args[1] if len(node.args) > 1 else keyword_nodes.get('safe')
            safe = '/' if safe_node is None and None not in keywords else self._literal(safe_node)
            if safe is not None and '\r' not in safe and '\n' not in safe:
                return _prove(result)
            return _revoke(result)
        if isinstance(target, str) and target in {'str', 'builtins.str'}:
            return result
        if receiver is not None and short == 'replace' and len(node.args) >= 2:
            old, new = self._literal(node.args[0]), self._literal(node.args[1])
            count = node.args[2] if len(node.args) > 2 else keyword_nodes.get('count')
            unlimited = count is None or (isinstance(count, ast.UnaryOp) and isinstance(count.op, ast.USub)
                                          and isinstance(count.operand, ast.Constant)
                                          and isinstance(count.operand.value, int) and count.operand.value > 0)
            if new is None or '\r' in new or '\n' in new:
                return _revoke(result)
            if unlimited and old in {'\r', '\n'}:
                return _prove(result, frozenset({_CR if old == '\r' else _LF}))
            return result
        if receiver is not None and short == 'format' and self._literal(receiver) is not None:
            if not self._plain_template(self._literal(receiver)):
                return _revoke(result)
            return self._composition([receiver, *node.args, *keyword_nodes.values()], result)
        # External return semantics, unquote/decode, and custom methods are
        # unknown. Preserve provenance and explicitly drop old header proofs.
        return _revoke(result)


class _HeaderAnalysis(flow._Analysis):
    flow_class = _HeaderFlow

    def __init__(self, tree):
        super().__init__(tree)
        self.steps = 0


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    suppressions = SourceSuppressions('python')
    errors = []
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text, tree = flow._parse_source(path)
            if not _has_sink(tree):
                continue
            effects = _HeaderAnalysis(tree).analyze()
        except (OSError, UnicodeError, SyntaxError, RecursionError, RuntimeError, flow.AnalysisLimit) as exc:
            errors.append(f'{path}: {type(exc).__name__}: {exc}')
            continue
        lines = text.splitlines()
        directives = suppressions.index(path, text)
        seen = set()
        for (_kind, line, column, _label), fact in sorted(effects.items()):
            unsafe = [trace for trace in fact if not _safe(trace)]
            if line in seen or directives.is_suppressed(line, RULE_ID) or not unsafe:
                continue
            seen.add(line)
            trace = min(unsafe, key=lambda item: (len(item.path), item.path, item.source))
            witness = ' -> '.join([*(trace.path or (trace.source,)), 'response header'])
            yield path, line, column, f'{witness}: {_source_line(lines, line)}'[:240]
    if errors:
        raise RuntimeError('incomplete header analysis: ' + '; '.join(errors[:8]))
