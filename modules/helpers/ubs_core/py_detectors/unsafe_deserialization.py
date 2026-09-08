"""ubs_core.py_detectors.unsafe_deserialization — unsafe deserialization loaders (bead 0xjg.5).

Port of run_unsafe_deserialization_checks (modules/ubs-python.sh 3587-3796):
an ast.NodeVisitor tracking module imports (incl. aliases and
sklearn.externals.joblib spellings) and flagging pickle-compatible loader
calls — marshal/dill/cloudpickle load*, joblib.load, jsonpickle.decode/
loads, shelve.open, pandas.read_pickle, yaml.unsafe_load[_all] — plus
numpy.load with allow_pickle=True and torch.load without weights_only=True.

GH #102 adds the yaml.load/yaml.load_all Loader classification. A call that
names a Loader (``Loader=`` keyword or second positional argument) is resolved
inside the file:

* SAFE — yaml.SafeLoader/CSafeLoader/BaseLoader/CBaseLoader (attribute or
  ``from yaml import`` name), or a class defined in this file whose bases all
  resolve to safe loaders and whose constructor registrations are benign.
* UNSAFE — yaml.Loader/CLoader/UnsafeLoader/CUnsafeLoader/FullLoader/
  CFullLoader, ``Loader=None`` (PyYAML < 6 falls back to FullLoader), a class
  inheriting from any of those, or a SafeLoader subclass that registers a
  ``python/`` tag, a ``construct_python_*`` constructor, or a constructor /
  method whose body reaches eval/exec/__import__/pickle/marshal/os.system.
* UNRESOLVED — a Loader imported from elsewhere, computed at runtime, or a
  class whose bases/constructor registrations cannot be resolved here. A
  reassuring class name never establishes safety.

A call with no Loader at all (stream argument only) stays with
``py.yaml-unsafe`` (ast-grep pack) and ``py.security.yaml-load`` (category-7
regex).

Same-file and previous-line `ubs:ignore` markers suppress a hit; hits dedupe
per (rule, line) within a file (legacy `seen_lines`).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.unsafe-deserialization"
CATEGORY = 7
TITLE = "Unsafe Python deserialization loader"
SEVERITY = "critical"
DESCRIPTION = ("Avoid pickle-compatible loaders for untrusted data; use JSON/schema formats "
               "or explicitly safe artifact loading")

YAML_UNSAFE_LOADER_RULE_ID = "py.security.yaml-unsafe-loader"
YAML_UNSAFE_LOADER_TITLE = "yaml.load with an unsafe Loader"
YAML_UNSAFE_LOADER_DESCRIPTION = (
    "yaml.Loader, UnsafeLoader and FullLoader (and their subclasses, or a loader that registers "
    "python/ tags) construct arbitrary Python objects; use yaml.safe_load or a SafeLoader subclass"
)
YAML_LOADER_UNRESOLVED_RULE_ID = "py.security.yaml-loader-unresolved"
YAML_LOADER_UNRESOLVED_TITLE = "yaml.load Loader not resolvable to SafeLoader"
YAML_LOADER_UNRESOLVED_DESCRIPTION = (
    "The Loader is imported, computed at runtime, or inherits from something outside this file; "
    "confirm it derives from yaml.SafeLoader/BaseLoader without python/ constructors (manual review)"
)

# Multi-rule detector contract (ubs_core.py_scan.run_detectors): find() yields
# (rule_id, path, line, col, detail) and RULES carries the per-rule metadata.
RULES = (
    (RULE_ID, CATEGORY, TITLE, SEVERITY, DESCRIPTION),
    (YAML_UNSAFE_LOADER_RULE_ID, CATEGORY, YAML_UNSAFE_LOADER_TITLE, "critical", YAML_UNSAFE_LOADER_DESCRIPTION),
    (YAML_LOADER_UNRESOLVED_RULE_ID, CATEGORY, YAML_LOADER_UNRESOLVED_TITLE, "warning", YAML_LOADER_UNRESOLVED_DESCRIPTION),
)

MODULE_CALLS = {
    'marshal': {'load', 'loads'},
    'dill': {'load', 'loads'},
    'cloudpickle': {'load', 'loads'},
    'joblib': {'load'},
    'jsonpickle': {'decode', 'loads'},
    'shelve': {'open'},
    'pandas': {'read_pickle'},
    'yaml': {'unsafe_load', 'unsafe_load_all'},
}
SPECIAL_CALLS = {
    'numpy': {'load'},
    'torch': {'load'},
}
MODULE_ALIASES = {
    'marshal': {'marshal'},
    'dill': {'dill'},
    'cloudpickle': {'cloudpickle'},
    'joblib': {'joblib', 'sklearn.externals.joblib'},
    'jsonpickle': {'jsonpickle'},
    'shelve': {'shelve'},
    'pandas': {'pandas'},
    'yaml': {'yaml'},
    'numpy': {'numpy'},
    'torch': {'torch'},
}
FROM_MODULES = {
    'marshal': 'marshal',
    'dill': 'dill',
    'cloudpickle': 'cloudpickle',
    'joblib': 'joblib',
    'sklearn.externals.joblib': 'joblib',
    'jsonpickle': 'jsonpickle',
    'shelve': 'shelve',
    'pandas': 'pandas',
    'yaml': 'yaml',
    'numpy': 'numpy',
    'torch': 'torch',
}

# yaml.load / yaml.load_all Loader classification (GH #102).
YAML_LOAD_FUNCS = {'load', 'load_all'}
SAFE_LOADERS = {'SafeLoader', 'CSafeLoader', 'BaseLoader', 'CBaseLoader'}
UNSAFE_LOADERS = {'Loader', 'CLoader', 'UnsafeLoader', 'CUnsafeLoader', 'FullLoader', 'CFullLoader'}
CONSTRUCTOR_REGISTRARS = {'add_constructor', 'add_multi_constructor'}
# Standard tags a strict SafeLoader subclass legitimately re-registers
# (yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG and friends).
DEFAULT_TAG_ATTRS = {'DEFAULT_MAPPING_TAG', 'DEFAULT_SEQUENCE_TAG', 'DEFAULT_SCALAR_TAG'}
# Calls inside a constructor/method body that turn a "safe" loader into an
# arbitrary-code path.
DANGEROUS_CALLS = {
    'eval', 'exec', 'compile', '__import__', 'builtins.__import__',
    'importlib.import_module', 'import_module',
    'pickle.load', 'pickle.loads', 'marshal.load', 'marshal.loads',
    'os.system', 'os.popen', 'subprocess.run', 'subprocess.call',
    'subprocess.check_call', 'subprocess.check_output', 'subprocess.Popen',
}
SAFE, UNSAFE, UNRESOLVED, NEUTRAL = 'safe', 'unsafe', 'unresolved', 'neutral'
_VERDICT_RANK = {NEUTRAL: 0, SAFE: 1, UNRESOLVED: 2, UNSAFE: 3}


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ''


def _source_line(lines, line_no):
    idx = line_no - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ''


def _has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def _is_true(node):
    return isinstance(node, ast.Constant) and node.value is True


def _keyword_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _worst(verdicts):
    """Combine verdicts: UNSAFE beats UNRESOLVED beats SAFE beats NEUTRAL."""
    worst = NEUTRAL
    for verdict in verdicts:
        if _VERDICT_RANK[verdict] > _VERDICT_RANK[worst]:
            worst = verdict
    return worst


def _body_reaches_dangerous_call(nodes) -> bool:
    for root in nodes:
        for node in ast.walk(root):
            if isinstance(node, ast.Call) and _call_name(node.func) in DANGEROUS_CALLS:
                return True
    return False


class _UnsafeDeserializerAnalyzer(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.modules = {key: set(value) for key, value in MODULE_ALIASES.items()}
        self.direct_calls = {}
        self.issues: list[tuple[str, int, str]] = []
        self.seen = set()
        # GH #102 loader resolution state (filled by collect()).
        self.yaml_load_aliases: dict[str, str] = {}   # local name -> load|load_all
        self.loader_imports: dict[str, str] = {}      # local name -> yaml class name
        self.classes: dict[str, ast.ClassDef] = {}
        self.functions: dict[str, ast.FunctionDef] = {}
        self.registrations: dict[str, list[ast.Call]] = {}  # class name -> add_*constructor calls

    def remember_issue(self, rule_id, line_no, detail=''):
        if _has_ignore(self.lines, line_no) or (rule_id, line_no) in self.seen:
            return
        self.seen.add((rule_id, line_no))
        self.issues.append((rule_id, line_no, detail))

    # ── pre-pass: classes, functions and constructor registrations ──────────
    def collect(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                self.classes.setdefault(node.name, node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)
            elif isinstance(node, ast.Call):
                target = self.registration_target(node)
                if target:
                    self.registrations.setdefault(target, []).append(node)

    def registration_target(self, call) -> str:
        """Class name a constructor registration applies to, or ''."""
        func = call.func
        if not isinstance(func, ast.Attribute) or func.attr not in CONSTRUCTOR_REGISTRARS:
            return ''
        owner = _call_name(func.value)
        if owner in self.modules['yaml']:
            # yaml.add_constructor(tag, fn, Loader=X) registers on X.
            loader = _keyword_value(call, 'Loader')
            return loader.id if isinstance(loader, ast.Name) else ''
        return owner if isinstance(func.value, ast.Name) else ''

    # ── imports ─────────────────────────────────────────────────────────────
    def visit_Import(self, node):
        for alias in node.names:
            canonical = FROM_MODULES.get(alias.name)
            if canonical:
                self.modules[canonical].add(alias.asname or alias.name)
            elif alias.name.endswith('.joblib'):
                self.modules['joblib'].add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        if module == 'sklearn.externals':
            for alias in node.names:
                if alias.name == 'joblib':
                    self.modules['joblib'].add(alias.asname or alias.name)
            self.generic_visit(node)
            return
        canonical = FROM_MODULES.get(module)
        if canonical:
            allowed = MODULE_CALLS.get(canonical, set()) | SPECIAL_CALLS.get(canonical, set())
            for alias in node.names:
                if alias.name in allowed:
                    self.direct_calls[alias.asname or alias.name] = f'{canonical}.{alias.name}'
        if module == 'yaml':
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name in YAML_LOAD_FUNCS:
                    self.yaml_load_aliases[local] = alias.name
                elif alias.name in SAFE_LOADERS or alias.name in UNSAFE_LOADERS:
                    self.loader_imports[local] = alias.name
        self.generic_visit(node)

    # ── legacy pickle-compatible loader calls ───────────────────────────────
    def canonical_call(self, node):
        name = _call_name(node.func)
        if name in self.direct_calls:
            return self.direct_calls[name]
        for canonical, funcs in {**MODULE_CALLS, **SPECIAL_CALLS}.items():
            for alias in self.modules.get(canonical, set()):
                for func in funcs:
                    if name == f'{alias}.{func}':
                        return f'{canonical}.{func}'
        if name.endswith('.joblib.load'):
            return 'joblib.load'
        return ''

    def is_unsafe_call(self, node):
        canonical = self.canonical_call(node)
        if not canonical:
            return False
        module, func = canonical.rsplit('.', 1)
        if module == 'numpy' and func == 'load':
            return _is_true(_keyword_value(node, 'allow_pickle'))
        if module == 'torch' and func == 'load':
            return not _is_true(_keyword_value(node, 'weights_only'))
        return True

    # ── GH #102: yaml.load Loader classification ────────────────────────────
    def yaml_load_call(self, node) -> bool:
        name = _call_name(node.func)
        if name in self.yaml_load_aliases:
            return True
        owner, _, func = name.rpartition('.')
        return bool(owner) and owner in self.modules['yaml'] and func in YAML_LOAD_FUNCS

    def loader_argument(self, call):
        loader = _keyword_value(call, 'Loader')
        if loader is not None:
            return loader
        if len(call.args) >= 2 and not isinstance(call.args[1], ast.Starred):
            return call.args[1]
        return None

    def classify_yaml_class(self, name) -> str:
        if name in SAFE_LOADERS:
            return SAFE
        if name in UNSAFE_LOADERS:
            return UNSAFE
        return UNRESOLVED

    def classify_loader(self, node, seen=frozenset()) -> str:
        if isinstance(node, ast.Constant) and node.value is None:
            return UNSAFE
        if isinstance(node, ast.Attribute):
            if _call_name(node.value) in self.modules['yaml']:
                return self.classify_yaml_class(node.attr)
            return UNRESOLVED
        if isinstance(node, ast.Name):
            if node.id in self.loader_imports:
                return self.classify_yaml_class(self.loader_imports[node.id])
            cls = self.classes.get(node.id)
            if cls is not None:
                return self.classify_class(cls, seen)
            if node.id == 'object':
                return NEUTRAL
            return UNRESOLVED
        return UNRESOLVED

    def classify_class(self, cls, seen=frozenset()) -> str:
        if cls.name in seen:
            return UNRESOLVED
        seen = seen | {cls.name}
        if not cls.bases:
            # A plain mixin/helper class defined here: not a loader lineage on
            # its own, but its methods still count for the owning class.
            return UNSAFE if _body_reaches_dangerous_call(cls.body) else NEUTRAL
        lineage = _worst(self.classify_loader(base, seen) for base in cls.bases)
        if lineage == NEUTRAL:
            return UNRESOLVED
        if lineage == UNSAFE:
            return UNSAFE
        if _body_reaches_dangerous_call(cls.body):
            return UNSAFE
        return _worst((lineage, self.classify_registrations(cls)))

    def classify_registrations(self, cls) -> str:
        verdicts = [SAFE]
        for call in self.registrations.get(cls.name, ()):
            verdicts.append(self.classify_registration(call, cls))
        return _worst(verdicts)

    def classify_registration(self, call, cls) -> str:
        tag = call.args[0] if call.args else _keyword_value(call, 'tag')
        if tag is None:
            tag = _keyword_value(call, 'tag_prefix')
        constructor = call.args[1] if len(call.args) >= 2 else _keyword_value(call, 'constructor')
        if constructor is None:
            constructor = _keyword_value(call, 'multi_constructor')
        tag_verdict = UNRESOLVED
        if isinstance(tag, ast.Constant) and isinstance(tag.value, str):
            tag_verdict = UNSAFE if 'python/' in tag.value else SAFE
        elif isinstance(tag, ast.Attribute) and tag.attr in DEFAULT_TAG_ATTRS:
            tag_verdict = SAFE
        if tag_verdict == UNSAFE:
            return UNSAFE
        return _worst((tag_verdict, self.classify_constructor(constructor, cls)))

    def classify_constructor(self, node, cls) -> str:
        if node is None:
            return UNRESOLVED
        if isinstance(node, ast.Lambda):
            return UNSAFE if _body_reaches_dangerous_call([node.body]) else SAFE
        name = _call_name(node)
        if not name:
            return UNRESOLVED
        leaf = name.rsplit('.', 1)[-1]
        if 'python' in leaf.lower():
            # construct_python_object, construct_python_apply, ...
            return UNSAFE
        func = self.functions.get(leaf) if isinstance(node, ast.Name) else None
        if func is None and isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            owner = node.value.id
            owner_cls = self.classes.get(owner)
            if owner_cls is not None:
                func = next((n for n in owner_cls.body
                             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == leaf), None)
            elif owner in self.modules['yaml'] or owner in self.loader_imports:
                # yaml.SafeLoader.construct_mapping / SafeConstructor.construct_yaml_map
                return SAFE
        if func is None:
            return UNRESOLVED
        return UNSAFE if _body_reaches_dangerous_call(func.body) else SAFE

    def check_yaml_load(self, node):
        loader = self.loader_argument(node)
        if loader is None:
            return  # no Loader at all: py.yaml-unsafe / py.security.yaml-load own this shape
        verdict = self.classify_loader(loader)
        if verdict == SAFE:
            return
        # NEUTRAL (``Loader=object`` or a bases-less class) is not a loader we
        # can vouch for either: report it for review like any unresolved one.
        try:
            loader_text = ast.unparse(loader)
        except Exception:
            loader_text = '<loader>'
        detail = f"Loader={loader_text} — {_source_line(self.lines, node.lineno)}"
        if verdict == UNSAFE:
            self.remember_issue(YAML_UNSAFE_LOADER_RULE_ID, node.lineno, detail)
        else:
            self.remember_issue(YAML_LOADER_UNRESOLVED_RULE_ID, node.lineno, detail)

    def visit_Call(self, node):
        if self.is_unsafe_call(node):
            self.remember_issue(RULE_ID, node.lineno, _source_line(self.lines, node.lineno))
        elif self.yaml_load_call(node):
            self.check_yaml_load(node)
        self.generic_visit(node)


def analyze_source(text: str) -> list[tuple[str, int, str]]:
    """(rule_id, line, detail) hits for one module's source; empty on syntax errors."""
    try:
        tree = ast.parse(text)
    except Exception:
        return []
    analyzer = _UnsafeDeserializerAnalyzer(text.splitlines())
    analyzer.collect(tree)
    analyzer.visit(tree)
    return analyzer.issues


def find(files: Sequence[Path]) -> Iterable[tuple[str, Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        for rule_id, line_no, detail in analyze_source(text):
            yield rule_id, path, line_no, 1, detail[:240]
