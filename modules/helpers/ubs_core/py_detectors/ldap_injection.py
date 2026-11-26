"""LDAP filter and DN flow with native receiver and escaping identities.

The shared Python solver owns control flow, aliases and local helper calls.
This adapter supplies the different python-ldap/ldap3 operand contracts and
keeps filter escaping separate from DN escaping. Opaque directory-shaped
calls retain the legacy conservative check; only a proved non-directory
receiver can exclude one. Sanitizer names alone never establish safety.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

from ubs_core.analyzers import taint_py as flow
from ubs_core.suppression import SourceSuppressions

RULE_ID = "py.security.ldap-injection"
CATEGORY = 7
TITLE = "Request-controlled LDAP filter or DN reaches directory sink"
SEVERITY = "critical"
DESCRIPTION = ("Escape LDAP filter values with escape_filter_chars(), escape DN fragments "
               "with escape_dn_chars(), or use fixed allow-lists before LDAP operations")

LDAP_SEARCH_METHODS = {
    'search', 'search_s', 'search_st', 'search_ext', 'search_ext_s',
    'paged_search', 'paged_search_s', 'paged_search_ext_s',
}
LDAP_DN_METHODS = {
    'add', 'add_s', 'delete', 'delete_s', 'modify', 'modify_s',
    'modify_dn', 'modify_dn_s', 'rename', 'rename_s', 'compare', 'compare_s',
    'simple_bind', 'simple_bind_s', 'bind', 'bind_s', 'rebind', 'rebind_s',
}
_SINK_METHODS = LDAP_SEARCH_METHODS | LDAP_DN_METHODS
_FILTER, _DN, _RESET = 'ldap:filter', 'ldap:dn', 'ldap:reset'
_PROOFS = frozenset({_FILTER, _DN})
_IMPORT, _MODULE_REF = '@ldap-import:', '@ldap-module:'
_CONNECTION, _METHOD, _SET = '@ldap-connection:', '@ldap-method:', '@ldap-builtin:set'
_SET_FACTORY = '@ldap-builtin:set-constructor'
_UNKNOWN_INSTANCE = '@ldap-instance:unproved'
_CHANGED_RECEIVER = '@ldap-receiver:changed'
_EXTEND, _STANDARD = '@ldap3-extension:extend', '@ldap3-extension:standard'
_MODULES = {
    'ldap', 'ldap.filter', 'ldap.dn', 'ldap.ldapobject',
    'ldap3', 'ldap3.core', 'ldap3.core.connection', 'ldap3.utils',
    'ldap3.utils.conv', 'ldap3.utils.dn', 'django_auth_ldap', 'django_auth_ldap.config',
}
_FACTORIES = {
    'ldap.initialize': 'python-ldap', 'ldap.open': 'python-ldap',
    'ldap.ldapobject.LDAPObject': 'python-ldap',
    'ldap.ldapobject.ReconnectLDAPObject': 'python-ldap',
    'ldap3.Connection': 'ldap3', 'ldap3.core.connection.Connection': 'ldap3',
}
_CONNECTION_CLASSES = frozenset({
    'ldap.ldapobject.LDAPObject', 'ldap.ldapobject.ReconnectLDAPObject',
    'ldap3.Connection', 'ldap3.core.connection.Connection',
})
_ENCODERS = {
    'ldap.filter.escape_filter_chars': _FILTER,
    'ldap.dn.escape_dn_chars': _DN,
    'ldap3.utils.conv.escape_filter_chars': _FILTER,
    'ldap3.utils.dn.escape_rdn': _DN,
}
_FILTER_FORMAT = 'ldap.filter.filter_format'
_SEARCH_CONSTRUCTOR = 'django_auth_ldap.config.LDAPSearch'
_KNOWN_IMPORTS = _MODULES | set(_FACTORIES) | set(_ENCODERS) | {_FILTER_FORMAT, _SEARCH_CONSTRUCTOR}
_REGEX_CALLABLES = frozenset({'search', 'compile'})
_REGEX_FLAGS = frozenset({'A', 'ASCII', 'I', 'IGNORECASE', 'L', 'LOCALE', 'M', 'MULTILINE',
                          'S', 'DOTALL', 'U', 'UNICODE', 'X', 'VERBOSE', 'DEBUG', 'NOFLAG'})
_LOCAL_CALLABLES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                    flow._BoundClassMethod, flow._FunctionValue, flow._ClosureValue)


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


def _source_line(lines, line):
    return lines[line - 1].strip() if 0 < line <= len(lines) else ''


def _request_source(node):
    name = _call_name(node)
    root = name.split('.', 1)[0]
    return name if root == 'request' or root.endswith('_request') else None


def _has_sink(tree, receiver_proof=None):
    # A saved method still contains its original attribute read. Keep the
    # prefilter syntactic and broad, before the semantic receiver proof.
    candidates = (node for node in ast.walk(tree)
                  if isinstance(node, ast.Attribute) and node.attr in _SINK_METHODS
                  or isinstance(node, ast.Name) and node.id in _SINK_METHODS | {'LDAPSearch'}
                  or isinstance(node, ast.ImportFrom) and any(alias.name == 'LDAPSearch' for alias in node.names))
    return any(receiver_proof is None or not receiver_proof.non_directory(node)
               for node in candidates)


def _prove(fact, domain):
    # Escaping for another grammar cannot preserve a prior grammar's proof:
    # DN escaping adds backslashes that a filter parser interprets differently.
    return frozenset(flow.TaintTrace(t.source, t.parameter,
                                    (t.sanitizers - _PROOFS) | {domain, _RESET}, t.path) for t in fact)


def _revoke(fact):
    return frozenset(flow.TaintTrace(t.source, t.parameter,
                                    (t.sanitizers - _PROOFS) | {_RESET}, t.path) for t in fact)


def _import_name(binding):
    if isinstance(binding, flow._BoundCallable):
        binding = binding.name
    return binding[len(_IMPORT):] if isinstance(binding, str) and binding.startswith(_IMPORT) else None


def _native_class_method(binding):
    imported = _import_name(binding)
    owner, _, method = (imported or '').rpartition('.')
    if owner in _CONNECTION_CLASSES and method in _SINK_METHODS:
        return _FACTORIES[owner], method
    return None


def _module_refs(binding):
    return frozenset(_MODULE_REF + name for choice in flow._binding_choices(binding)
                     if (name := _import_name(choice)) in _MODULES)


def _native_receiver(binding):
    return isinstance(binding, str) and (binding.startswith(_CONNECTION) or binding in {_EXTEND, _STANDARD})


class _ReceiverProof:
    """Small structural proof for builtin sets, including owned fields.

    Flow-sensitive local aliases and rebindings are handled by the solver.
    Reflective namespace writes invalidate the builtin proof. Instance field
    exclusion is narrower: one unconditional constructor assignment, no
    alternate field stores, and no custom attribute protocol or inheritance.
    No receiver spelling such as ``items`` or ``parameters`` is trusted.
    """
    def __init__(self, engine):
        self.engine = engine
        tree = engine.tree
        nodes = tuple(ast.walk(tree))
        parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
        self.class_locals = {node: flow._local_names(node) for node in nodes if isinstance(node, ast.ClassDef)}
        attribute_writes = {node.attr for node in nodes if isinstance(node, ast.Attribute)
                            and isinstance(node.ctx, (ast.Store, ast.Del))}
        readonly_vars = set()
        for node in nodes:
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'vars'
                    and len(node.args) == 1 and not node.keywords and isinstance(node.args[0], ast.Name)):
                continue
            scope = node
            while scope not in engine.locals and scope not in self.class_locals:
                scope = parents.get(scope)
            member, call = parents.get(node), parents.get(parents.get(node))
            if ('vars' not in attribute_writes and self.builtin_visible('vars', scope)
                    and self.builtins_module(node.args[0].id, scope)
                    and isinstance(member, ast.Attribute) and member.attr == 'items'
                    and isinstance(call, ast.Call) and call.func is member and not call.args and not call.keywords):
                readonly_vars.add(node)
        self.reflection = any(
            isinstance(node, ast.Name) and node.id in {
                'globals', 'locals', 'exec', 'eval', '__builtins__', 'currentframe', '_getframe'}
            or isinstance(node, ast.Name) and node.id == 'vars' and parents.get(node) not in readonly_vars
            or isinstance(node, ast.Attribute) and node.attr in {
                'f_locals', 'f_globals', '__dict__', '__globals__', '__closure__', 'currentframe', '_getframe'}
            or isinstance(node, ast.Attribute) and node.attr == 'cell_contents'
            and not (isinstance(node.ctx, ast.Load) and isinstance(parents.get(node), ast.Call)
                     and parents[node].func is node)
            for node in nodes)
        reflected_fields = set()
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node.func)
            leaf = name.rsplit('.', 1)[-1]
            if leaf not in {'setattr', 'delattr', '__setattr__', '__delattr__'}:
                continue
            position = 1 if leaf in {'setattr', 'delattr'} or name.startswith('object.') else 0
            attribute = node.args[position] if position < len(node.args) else None
            reflected_fields.update(self.attribute_names(attribute, node, parents))
        self.reflection |= 'vars' in reflected_fields
        factory_shadowed = bool({None, 'set'} & reflected_fields) or any(
            isinstance(node, ast.Attribute) and node.attr == 'set' and isinstance(node.ctx, (ast.Store, ast.Del))
            or isinstance(node, (ast.Import, ast.ImportFrom)) and any(
                alias.name == '*' for alias in node.names)
            for node in nodes)
        self.builtin_set = not self.reflection and not factory_shadowed
        self.applicability_exposed = (self.reflection or engine.generator_builtin_reflection
                                      or engine.generator_namespace_exposed or engine.generator_frame_exposed
                                      or engine.generator_literal_authority_exposed)
        self.attribute_writes = attribute_writes | reflected_fields
        self.named_writes = {name for node in nodes if isinstance(node, (ast.Global, ast.Nonlocal))
                             for name in node.names}
        self.name_reads = {}
        for node in nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                self.name_reads.setdefault(node.id, []).append(node)
        self.regex_imports = []
        for node in nodes:
            if isinstance(node, ast.Import):
                self.regex_imports.extend((node, alias.asname or alias.name, None)
                                          for alias in node.names if alias.name == 're')
            elif isinstance(node, ast.ImportFrom) and node.module == 're' and not node.level:
                self.regex_imports.extend((node, alias.asname or alias.name, alias.name)
                                          for alias in node.names)
        self.regex_authority = None
        self.non_directory_proofs = {}
        self.fields = {}
        # A method named cell_contents or a read-only vars(builtins) inventory
        # is not a write to an instance field. Still reject real namespace
        # mutation/escape before using the narrower constructor-field proof.
        field_reflection = None in reflected_fields or self.reflection
        if field_reflection:
            return
        writes = {}
        for node in nodes:
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                writes.setdefault(node.attr, []).append(node)
        for owner in (node for node in nodes if isinstance(node, ast.ClassDef)):
            methods = [node for node in owner.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if (owner.bases or owner.keywords or owner.decorator_list
                    or any(method.name in {'__getattr__', '__getattribute__', '__setattr__', '__delattr__'}
                           for method in methods)
                    or any(not isinstance(decorator, ast.Name)
                           or decorator.id not in {'staticmethod', 'classmethod'}
                           or not self.builtin_visible(decorator.id, owner)
                           or decorator.id in reflected_fields | attribute_writes
                           for method in methods for decorator in method.decorator_list)):
                continue
            init = next((method for method in methods if method.name == '__init__'), None)
            if init is None or init.decorator_list or not init.args.args:
                continue
            receiver = init.args.args[0].arg
            # Passing or returning the complete instance can expose its
            # fields to an opaque mutator. Direct attribute reads/calls alone
            # cannot replace a builtin set's identity.
            instance_methods = [method for method in methods if method.args.args and not method.decorator_list]
            escapes = {method: [node for node in ast.walk(method)
                               if isinstance(node, ast.Name) and node.id == method.args.args[0].arg
                               and (not isinstance(node.ctx, ast.Load)
                                    or not isinstance(parents.get(node), ast.Attribute)
                                    or parents[node].value is not node)]
                       for method in instance_methods}
            # An earlier escape retains aliases after a later assignment.
            # An ordinary method may also expose self transitively. Until the
            # shared heap proves those lifetimes, retain the conservative
            # directory-shaped finding for every field of that class.
            if any(escapes.values()):
                continue
            fields = set()
            for statement in init.body:
                target = (statement.targets[0] if isinstance(statement, ast.Assign) and len(statement.targets) == 1
                          else statement.target if isinstance(statement, ast.AnnAssign) else None)
                if (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                        and target.value.id == receiver
                        and writes.get(target.attr) == [target]
                        and target.attr not in reflected_fields
                        and (isinstance(statement.value, (ast.Set, ast.SetComp))
                             or self.builtin_set and self.builtin_visible('set', init)
                             and isinstance(statement.value, ast.Call) and isinstance(statement.value.func, ast.Name)
                             and statement.value.func.id == 'set')):
                    fields.add(target.attr)
            for method in instance_methods:
                self.fields[method] = (method.args.args[0].arg, fields)

    @staticmethod
    def attribute_names(attribute, call, parents):
        if isinstance(attribute, ast.Constant) and isinstance(attribute.value, str):
            return {attribute.value}
        if not isinstance(attribute, ast.Name):
            return {None}
        # A finite literal loop writes exactly its enumerated names. Rebinding
        # the iterator variable inside that loop destroys the proof; arbitrary
        # expressions and unknown iterables remain namespace-wide mutations.
        owner = parents.get(call)
        while owner is not None and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if (isinstance(owner, ast.For) and isinstance(owner.target, ast.Name)
                    and owner.target.id == attribute.id):
                if not (isinstance(owner.iter, (ast.Tuple, ast.List))
                        and all(isinstance(value, ast.Constant) and isinstance(value.value, str)
                                for value in owner.iter.elts)):
                    return {None}
                for node in ast.walk(owner):
                    if node is owner.target:
                        continue
                    if (isinstance(node, ast.Name) and node.id == attribute.id and isinstance(node.ctx, (ast.Store, ast.Del))
                            or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler))
                            and node.name == attribute.id
                            or isinstance(node, (ast.Import, ast.ImportFrom)) and any(
                                (alias.asname or alias.name.split('.')[0]) == attribute.id for alias in node.names)
                            or flow._pattern_capture(node) == attribute.id):
                        return {None}
                return {value.value for value in owner.iter.elts}
            owner = parents.get(owner)
        return {None}

    def lexical_scopes(self, scope):
        first = True
        while scope is not None:
            if first or not isinstance(scope, ast.ClassDef):
                yield scope
            first = False
            scope = self.engine.enclosing(scope)

    def builtin_visible(self, name, scope):
        for owner in self.lexical_scopes(scope):
            if name in self.engine.locals.get(owner, self.class_locals.get(owner, ())):
                return False
            if name in self.engine.declared_globals.get(owner, ()):
                return name not in self.engine.global_names
        return True

    def builtins_module(self, name, scope):
        for owner in self.lexical_scopes(scope):
            if name not in self.engine.locals.get(owner, self.class_locals.get(owner, ())):
                continue
            binders = self.engine.generator_binders.get(owner, {}).get(name, ())
            return (len(binders) == 1 and isinstance(binders[0], ast.Import)
                    and any(alias.name == 'builtins' and (alias.asname or alias.name) == name
                            for alias in binders[0].names))
        return False

    def owned_set(self, scope, node):
        receiver, fields = self.fields.get(scope, (None, ()))
        return (isinstance(node, ast.Attribute) and node.attr in fields
                and isinstance(node.value, ast.Name) and node.value.id == receiver)

    def single_binding(self, node):
        """Resolve one lexical binding, refusing writes through another frame.

        This is an applicability proof, not a replacement for flow analysis.
        Multiple stores, parameters, comprehension targets and class bodies
        deliberately retain the full semantic path.
        """
        if node.id in self.named_writes:
            return None
        child = node
        parent = self.engine.parents.get(child)
        while parent is not None:
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                if (child is parent.args or child in getattr(parent, 'decorator_list', ())
                        or child is getattr(parent, 'returns', None)):
                    # Defaults/decorators execute in the enclosing frame, not
                    # the function whose argument/local names they precede.
                    return None
                break
            child, parent = parent, self.engine.parents.get(parent)
        for scope in self.lexical_scopes(self.engine.enclosing(node)):
            if isinstance(scope, ast.ClassDef):
                return None
            if node.id in self.engine.locals.get(scope, ()):
                binders = self.engine.generator_binders.get(scope, {}).get(node.id, ())
                return binders[0] if len(binders) == 1 else None
        return None

    def regex_callable_unexposed(self, node, active=frozenset()):
        # re.search/compile are mutable Python functions. Capturing a private
        # alias is safe; passing the function to opaque code can rewrite its
        # __code__ or globals and must invalidate even earlier captures.
        if node in active or len(active) >= 32:
            return False
        parent = self.engine.parents.get(node)
        if isinstance(parent, ast.Call) and parent.func is node:
            return True
        target = (parent.targets[0] if isinstance(parent, ast.Assign) and len(parent.targets) == 1
                  else parent.target if isinstance(parent, ast.AnnAssign) else None)
        if (not isinstance(target, ast.Name) or getattr(parent, 'value', None) is not node
                or self.single_binding(target) is not target):
            return False
        for use in self.name_reads.get(target.id, ()):
            binding = self.single_binding(use)
            if binding is None:
                return False
            if binding is target and not self.regex_callable_unexposed(use, active | {node}):
                return False
        return True

    def regex_unexposed(self):
        if self.regex_authority is not None:
            return self.regex_authority
        self.regex_authority = False
        if self.applicability_exposed or {None, 'search', 'compile', '__code__'} & self.attribute_writes:
            return False
        # All aliases refer to the same mutable re module. A write through a
        # second import, an exposed internal (_compile, caches, compiler), or
        # an escaped function revokes authority for every import in this file.
        for binder, name, member in self.regex_imports:
            if member is not None and member not in _REGEX_CALLABLES | _REGEX_FLAGS:
                return False
            for use in self.name_reads.get(name, ()):
                binding = self.single_binding(use)
                # An ambiguous alias can still denote this import on one
                # branch. Only a proved distinct lexical binding is private.
                if binding is None:
                    return False
                if binding is not binder:
                    continue
                if member is None:
                    attribute = self.engine.parents.get(use)
                    if (not isinstance(attribute, ast.Attribute) or attribute.value is not use
                            or not isinstance(attribute.ctx, ast.Load)
                            or attribute.attr not in _REGEX_CALLABLES | _REGEX_FLAGS):
                        return False
                    if attribute.attr in _REGEX_CALLABLES and not self.regex_callable_unexposed(attribute):
                        return False
                elif member in _REGEX_CALLABLES and not self.regex_callable_unexposed(use):
                    return False
        self.regex_authority = True
        return True

    def static_receiver(self, node, active=None):
        if self.applicability_exposed:
            return None
        active = set() if active is None else active
        if node in active or len(active) >= 32:
            return None
        active = active | {node}
        if isinstance(node, (ast.Set, ast.SetComp)):
            return 'set'
        if isinstance(node, ast.Name):
            binder = self.single_binding(node)
            if isinstance(binder, (ast.Import, ast.ImportFrom)):
                if getattr(binder, 'level', 0) or not self.regex_unexposed():
                    return None
                for alias in binder.names:
                    if (alias.asname or alias.name.split('.')[0]) != node.id:
                        continue
                    if isinstance(binder, ast.Import) and alias.name == 're':
                        return 're'
                    if isinstance(binder, ast.ImportFrom) and binder.module == 're':
                        if alias.name in {'search', 'compile'}:
                            return 're.' + alias.name
                return None
            if not isinstance(binder, ast.Name):
                return None
            statement = self.engine.parents.get(binder)
            if (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                    and statement.targets[0] is binder
                    or isinstance(statement, ast.AnnAssign) and statement.target is binder):
                return self.static_receiver(statement.value, active)
            return None
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Name) and node.func.id == 'set'
                    and self.builtin_set
                    and self.builtin_visible('set', self.engine.enclosing(node))):
                return 'set'
            if self.static_receiver(node.func, active) == 're.compile':
                return 're.Pattern'
        if isinstance(node, ast.Attribute):
            parent = self.static_receiver(node.value, active)
            if parent == 're' and node.attr in {'search', 'compile'}:
                return 're.' + node.attr
            if parent == 're.Pattern' and node.attr == 'search':
                return 're.Pattern.search'
            if parent == 'set' and node.attr == 'add':
                return 'set.add'
        return None

    def non_directory(self, node):
        """Exclude only proved native operations before imposing LDAP work.

        The regex module and builtin sets share common LDAP method names.
        A file containing only those operations has no LDAP sink to analyze;
        unrelated generator protocols must not make that detector partial.
        Any unresolved candidate keeps the original whole-file analysis and
        its completeness requirements, including all called helper scopes.
        """
        if node not in self.non_directory_proofs:
            self.non_directory_proofs[node] = self.static_receiver(node) in {
                'set.add', 're.search', 're.Pattern.search'}
        return self.non_directory_proofs[node]


class _LDAPFlow(flow._Flow):
    @staticmethod
    def substitute_trace(trace, actual, call_name):
        if trace.parameter is None:
            return frozenset({trace})
        if _RESET in trace.sanitizers:
            actual = _revoke(actual)
        for sanitizer in trace.sanitizers - {_RESET}:
            actual = flow._sanitize(actual, sanitizer)
        steps = trace.path[1:] if trace.parameter.startswith('@') else trace.path
        return flow._advance(actual, call_name, *steps)

    @staticmethod
    def incomplete_result(fact):
        return _revoke(flow._Flow.incomplete_result(fact))

    def effect(self, kind, node, label, fact):
        if kind in {'ldap-filter', 'ldap-dn'} and fact:
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
        local = self.engine.locals.get(self.scope, set())
        changed_globals = set(self.context_globals)
        for name in set(state.bindings) | set(self.engine.globals.bindings):
            binding = state.bindings.get(name, self.engine.globals.bindings.get(name))
            refs = _module_refs(binding) | state.references.get(name, flow.NO_REFERENCES)
            if not refs & module_refs:
                continue
            choices = [None if _import_name(choice) in _MODULES else choice
                       for choice in flow._binding_choices(binding)]
            if name not in local and name in self.engine.global_symbols:
                value, global_refs, _binding = self.engine.global_symbols[name]
                state.setdefault(name, value)
                state.references[name] = refs | global_refs
                changed_globals.add(name)
            self.write_name(state, name, state.get(name, flow.CLEAN), flow._join_bindings(*choices),
                            state.references.get(name, flow.NO_REFERENCES))
        self.context_globals = tuple(sorted(changed_globals))

    def statement(self, node, state):
        if isinstance(node, ast.ImportFrom) and any(alias.name == '*' for alias in node.names):
            for name, binding in tuple(state.bindings.items()):
                replacement = flow._join_bindings(*(
                    None if _import_name(choice) else choice for choice in flow._binding_choices(binding)))
                self.write_name(state, name, state.get(name, flow.CLEAN), replacement,
                                state.references.get(name, flow.NO_REFERENCES))
            return state
        result = super().statement(node, state)
        if result is not None and isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or alias.name.split('.')[0]
                name = (f'{node.module}.{alias.name}' if isinstance(node, ast.ImportFrom)
                        else alias.name if alias.asname else local)
                if name in _KNOWN_IMPORTS and not getattr(node, 'level', 0):
                    refs = frozenset({_MODULE_REF + name}) if name in _MODULES else flow.NO_REFERENCES
                    owner = name.rsplit('.', 1)[0]
                    invalid = _MODULE_REF + name in state.mutated or _MODULE_REF + owner in state.mutated
                    self.write_name(result, local, result.get(local, flow.CLEAN),
                                    None if invalid else _IMPORT + name, refs)
        return result

    def source(self, node, state, candidate=None):
        fact = super().source(node, state, candidate)
        name = candidate or _call_name(node)
        request = _request_source(node)
        if request and isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
            fact = flow.join_facts(fact, frozenset({flow.TaintTrace(request, path=(request,))}))
        if isinstance(node, ast.Call) and name.rstrip('(') in {'sys.stdin.read', 'sys.stdin.readline'}:
            return flow.join_facts(fact, frozenset({flow.TaintTrace(name, path=(name,))}))
        return fact

    def expr(self, node, state):
        if node is None or not state.reachable:
            return flow.CLEAN
        fact = super().expr(node, state)
        binding = self.expression_bindings.get(node)
        if isinstance(node, ast.Name):
            if (node.id == 'set' and self.engine.receiver_proof.builtin_set
                    and self.engine.receiver_proof.builtin_visible('set', self.scope)):
                binding = _SET_FACTORY
            refs = self.expression_references.get(node, flow.NO_REFERENCES) | _module_refs(binding)
            self.expression_references[node] = refs
            if refs & state.mutated:
                binding = flow._join_bindings(*(
                    None if _import_name(choice) in _MODULES else
                    _CHANGED_RECEIVER if _native_receiver(choice) else choice
                    for choice in flow._binding_choices(binding)))
            if _request_source(node) and any(choice is None or isinstance(choice, flow._SymbolicValue)
                                            for choice in flow._binding_choices(binding)):
                fact = flow.join_facts(fact, frozenset({flow.TaintTrace(node.id, path=(node.id,))}))
        elif isinstance(node, ast.Attribute):
            parent_binding = self.expression_bindings.get(node.value)
            if node.attr in _SINK_METHODS:
                self.require_value(parent_binding)
            choices = []
            refs = self.expression_references.get(node.value, flow.NO_REFERENCES)
            for parent in flow._binding_choices(parent_binding):
                imported = _import_name(parent)
                if imported is not None:
                    choices.append(None if refs & state.mutated else _IMPORT + f'{imported}.{node.attr}')
                elif parent == _CHANGED_RECEIVER:
                    choices.append(flow._BoundCallable(_CHANGED_RECEIVER + '.' + node.attr, refs,
                        self.expression_facts.get(node.value, flow.CLEAN), True))
                elif parent == _CONNECTION + 'ldap3' and node.attr == 'extend':
                    choices.append(_EXTEND)
                elif parent == _EXTEND and node.attr == 'standard':
                    choices.append(_STANDARD)
                elif parent == _STANDARD and node.attr == 'paged_search':
                    choices.append(flow._BoundCallable(_METHOD + 'ldap3:paged_search', refs,
                        self.expression_facts.get(node.value, flow.CLEAN), True, receiver_binding=parent))
                elif isinstance(parent, str) and parent.startswith(_CONNECTION):
                    choices.append(flow._BoundCallable(_METHOD + parent[len(_CONNECTION):] + ':' + node.attr,
                        refs, self.expression_facts.get(node.value, flow.CLEAN), True, receiver_binding=parent))
                elif parent == _SET:
                    choices.append(flow._BoundCallable(_SET + '.' + node.attr, refs,
                        self.expression_facts.get(node.value, flow.CLEAN), True, receiver_binding=_SET))
                else:
                    choices.extend(None if _import_name(choice) else choice
                                   for choice in flow._binding_choices(binding))
            binding = flow._join_bindings(*choices)
            module_refs = _module_refs(binding)
            if module_refs:
                self.expression_references[node] = refs | module_refs
            elif all(_import_name(choice) in set(_ENCODERS) | {_FILTER_FORMAT}
                     for choice in flow._binding_choices(binding)):
                self.expression_references[node] = flow.NO_REFERENCES
        owned_set = self.engine.receiver_proof.owned_set(self.scope, node)
        if owned_set:
            receiver_binding = self.expression_bindings.get(node.value)
            self.require_value(receiver_binding)
            receiver_name = self.engine.receiver_proof.fields[self.scope][0]
            owned_set = all(isinstance(choice, flow._SymbolicValue) and choice.parameter == receiver_name
                            for choice in flow._binding_choices(receiver_binding))
        if (isinstance(node, (ast.Set, ast.SetComp)) and not self.engine.receiver_proof.reflection) or owned_set:
            binding = _SET
        self.expression_bindings[node] = binding
        self.expression_facts[node] = fact
        return fact

    def expression(self, node, state):
        fact = super().expression(node, state)
        # Field-insensitive provenance cannot prove another selected member.
        # Per-source proofs keep fresh components visible in compositions.
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return _revoke(fact)
        if isinstance(node, ast.BinOp) and not isinstance(node.op, (ast.Add, ast.Mod)):
            return _revoke(fact)
        return fact

    def assign(self, target, fact, state, value=None, *, target_references=None, deleting=False):
        if isinstance(target, ast.Attribute):
            if target_references is None:
                self.expr(target.value, state)
                target_references = self.expression_references.get(target.value, flow.NO_REFERENCES)
            binding = self.expression_bindings.get(target.value)
            self.require_value(binding)
            if any(_native_receiver(choice) or _import_name(choice) in _FACTORIES
                   for choice in flow._binding_choices(binding)):
                raise flow.AnalysisLimit('native LDAP receiver or class mutation is unresolved; analysis is incomplete')
        super().assign(target, fact, state, value, target_references=target_references, deleting=deleting)

    def _operands(self, node, inputs, state, positions, names):
        actual = self.call_positions(node, inputs.arguments, state)
        selected = [actual[index][1] for index in positions if index < len(actual)]
        selected.extend(inputs.keywords.get(name, flow.CLEAN) for name in names)
        if any(isinstance(expression, (ast.Starred, flow._ArgumentExpansion))
               for expression, _fact, _binding, _refs in actual):
            # Unknown expansion may shift an argument into a sensitive slot.
            selected.extend(fact for _expression, fact, _binding, _refs in actual)
        selected.append(inputs.keywords.get(None, flow.CLEAN))
        return flow.join_facts(*selected)

    def _sinks(self, node, state, target, name, inputs):
        if name.startswith(_CHANGED_RECEIVER):
            raise flow.AnalysisLimit('native LDAP receiver escaped before use; analysis is incomplete')
        if (isinstance(target, _LOCAL_CALLABLES) or name.startswith(_SET + '.')
                or self.engine.receiver_proof.non_directory(node.func)):
            return
        flavor, receiver_offset = None, 0
        unbound = _native_class_method(target)
        if name.startswith(_METHOD):
            flavor, short = name[len(_METHOD):].split(':', 1)
        elif unbound is not None:
            # A class-qualified or saved unbound function still has its
            # native API signature. Its explicit self precedes positional
            # operands; keyword names keep their ordinary meaning.
            flavor, short = unbound
            receiver_offset = 1
        else:
            short = node.func.attr if isinstance(node.func, ast.Attribute) else name.rsplit('.', 1)[-1]
        if short in LDAP_SEARCH_METHODS:
            # python-ldap: (base, scope, filterstr). ldap3: (base, filter,
            # scope). Both have a DN operand independent of the filter.
            filter_position = 2 if flavor == 'python-ldap' or short not in {'search', 'paged_search'} else 1
            filter_names = {'filterstr'} if flavor == 'python-ldap' else {'search_filter'} if flavor == 'ldap3' else {
                'search_filter', 'filterstr', 'ldap_filter'}
            base_names = {'base'} if flavor == 'python-ldap' else {'search_base'} if flavor == 'ldap3' else {
                'base', 'base_dn', 'search_base'}
            self.effect('ldap-filter', node, 'LDAP filter', self._operands(
                node, inputs, state, (filter_position + receiver_offset,), filter_names))
            self.effect('ldap-dn', node, 'LDAP search base', self._operands(
                node, inputs, state, (receiver_offset,), base_names))
        if short in LDAP_DN_METHODS:
            positions = (0,)
            names = {'dn', 'user', 'user_dn', 'bind_dn', 'base_dn'}
            if short in {'modify_dn', 'modify_dn_s'}:
                positions = (0, 1, 3)
                names |= {'relative_dn', 'new_superior'}
            elif short in {'rename', 'rename_s'}:
                positions = (0, 1, 2)
                names |= {'newrdn', 'newsuperior'}
            self.effect('ldap-dn', node, 'LDAP distinguished name', self._operands(
                node, inputs, state, tuple(index + receiver_offset for index in positions), names))
        if _import_name(target) == _SEARCH_CONSTRUCTOR or short == 'LDAPSearch':
            self.effect('ldap-filter', node, 'LDAPSearch filter', self._operands(
                node, inputs, state, (2,), {'filterstr'}))
            self.effect('ldap-dn', node, 'LDAPSearch base', self._operands(
                node, inputs, state, (0,), {'base_dn'}))

    def invoke(self, node, state, callee, inputs, *, resumed=None):
        if resumed is not None:
            return super().invoke(node, state, callee, inputs, resumed=resumed)
        target = callee.binding
        name = (target.name if isinstance(target, flow._BoundCallable)
                else target if isinstance(target, str) else callee.fallback_name) or ''
        self._sinks(node, state, target, name, inputs)
        local = isinstance(target, _LOCAL_CALLABLES)
        function = target
        while isinstance(function, (flow._FunctionValue, flow._ClosureValue)):
            function = function.function
        if (function in self.engine.receiver_proof.fields and not isinstance(target, flow._BoundClassMethod)
                and self.engine.receiver_proof.fields[function][1]):
            # Python permits Holder.method(arbitrary_object, ...), including
            # a saved method or callback. A constructor-field fact describes
            # ordinary instance entry, not an arbitrary supplied first arg.
            # The core intentionally collapses unknown callable arguments;
            # retain this domain's finite unknown-receiver identity so its
            # context cannot reuse the generic constructor-field exclusion.
            parameter = self.engine.receiver_proof.fields[function][0]
            receiver = node.args[0] if node.args else inputs.keyword_nodes.get(parameter)
            if receiver is None or isinstance(receiver, ast.Starred):
                raise flow.AnalysisLimit('unbound LDAP field receiver expansion is unresolved; analysis is incomplete')
            binding = self.expression_bindings.get(receiver)
            self.expression_bindings[receiver] = flow._join_bindings(*(
                _UNKNOWN_INSTANCE if choice is None or isinstance(choice, flow._SymbolicValue) else choice
                for choice in flow._binding_choices(binding)))
        if not local and _native_class_method(target) is None:
            for expression in (*node.args, *inputs.keyword_nodes.values()):
                if any(_native_receiver(choice)
                       for choice in flow._binding_choices(self.expression_bindings.get(expression))):
                    # An opaque consumer can replace an object's methods. It
                    # need not perform a directory operation itself (for
                    # example SimpleNamespace stores a supplied connection).
                    # Invalidate later receiver reads through all aliases;
                    # methods captured before escape keep their own callable.
                    self.mutate(self.expression_references.get(expression, flow.NO_REFERENCES), flow.CLEAN, state)
                if _module_refs(self.expression_bindings.get(expression)):
                    self.mutate(self.expression_references.get(expression, flow.NO_REFERENCES), flow.CLEAN, state)
        result = super().invoke(node, state, callee, inputs, resumed=resumed)
        if local:
            return result
        imported = _import_name(target)
        if imported in _FACTORIES:
            self.expression_bindings[node] = _CONNECTION + _FACTORIES[imported]
            return flow.CLEAN
        if name == _SET_FACTORY:
            self.expression_bindings[node] = _SET
        if imported in _ENCODERS:
            return _prove(result, _ENCODERS[imported])
        if imported == _FILTER_FORMAT:
            template = self._operands(node, inputs, state, (0,), {'filter_template'})
            values = self._operands(node, inputs, state, (1,), {'assertion_values'})
            return flow.join_facts(_revoke(template), _prove(values, _FILTER))
        if name in {'str', 'builtins.str'}:
            return result
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            if isinstance(self.expression_bindings.get(node.func.value), flow._LiteralString):
                return result
        return _revoke(result)


class _LDAPAnalysis(flow._Analysis):
    flow_class = _LDAPFlow

    def __init__(self, tree):
        super().__init__(tree)
        self.receiver_proof = _ReceiverProof(self)


class LDAPAnalysisLimit(flow.AnalysisLimit, RuntimeError):
    """Only bounded semantic failures were observed across LDAP sources."""


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    suppressions = SourceSuppressions('python')
    errors, components = [], []
    semantic_only = True
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text, tree = flow._parse_source(path)
            if not _has_sink(tree):
                continue
            analyzer = _LDAPAnalysis(tree)
            if not _has_sink(tree, analyzer.receiver_proof):
                continue
            analyzer.source_path = path
            effects = analyzer.analyze()
        except (OSError, UnicodeError, SyntaxError, RecursionError, RuntimeError, flow.AnalysisLimit) as exc:
            errors.append(f'{path}: {type(exc).__name__}: {exc}')
            cause = exc
            while isinstance(cause, flow.AnalysisLimit):
                cause = cause.__cause__
            semantic_only = semantic_only and cause is None
            components.extend(getattr(exc, 'components', ()))
            effects = exc.effects if isinstance(exc, flow.AnalysisLimit) else {}
            if not effects:
                continue
        lines = text.splitlines()
        directives = suppressions.index(path, text)
        seen = set()
        for (kind, line, column, label), fact in sorted(effects.items(), key=lambda item: item[0][1:]):
            domain = _FILTER if kind == 'ldap-filter' else _DN
            unsafe = [trace for trace in fact if domain not in trace.sanitizers]
            if line in seen or directives.is_suppressed(line, RULE_ID) or not unsafe:
                continue
            seen.add(line)
            trace = min(unsafe, key=lambda item: (len(item.path), item.path, item.source))
            witness = ' -> '.join([*(trace.path or (trace.source,)), label])
            yield path, line, column, f'{witness}: {_source_line(lines, line)}'[:240]
    if errors:
        message = 'incomplete LDAP analysis: ' + '; '.join(errors[:8])
        if semantic_only:
            raise LDAPAnalysisLimit(message, components=components)
        raise RuntimeError(message)
