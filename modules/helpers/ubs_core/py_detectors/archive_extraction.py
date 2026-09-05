"""ubs_core.py_detectors.archive_extraction — category 7 security (bead 0xjg.5).

Port of run_archive_extraction_checks (modules/ubs-python.sh 5197-5405):
flags tarfile/zipfile ``extract()``/``extractall()`` calls whose target is not
demonstrably safe. Tracks handles created by ``tarfile.open()`` /
``zipfile.ZipFile()`` (direct calls, assignments, or ``with``-bound names) so
only real archive extractions are considered; a bare ``extractall`` on an
unknown owner counts only when an archive module is imported. Suppressed when
a tar ``extractall`` carries ``filter='data'`` / ``tarfile.data_filter``, or
when ``extract`` / ``members=`` calls have a validation marker (safe_extract,
resolve, normpath, a '..' literal, ...) within the preceding 16 lines.

Same-file and previous-line ``ubs:ignore`` markers suppress a hit.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable, Sequence

RULE_ID = "py.security.archive-extraction"
CATEGORY = 7
TITLE = "Archive extraction path traversal risk"
SEVERITY = "critical"
DESCRIPTION = (
    "Validate every archive member stays under the destination, "
    "or use tarfile extraction filters where available"
)

SAFE_CONTEXT_RE = re.compile(
    r'\b(?:safe_extract|safe_members|validate_archive|validate_member|is_safe_archive|commonpath|is_relative_to|resolve|normpath|abspath)\b'
    r'|\.{2}',
    re.IGNORECASE,
)


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ''


def _call_is_tar_open(call, tar_modules, tar_open_names):
    name = _call_name(call.func)
    return name in tar_open_names or any(name == f"{module}.open" for module in tar_modules)


def _call_is_zip_open(call, zip_modules, zip_ctor_names):
    name = _call_name(call.func)
    return name in zip_ctor_names or any(name == f"{module}.ZipFile" for module in zip_modules)


def _mark_archive_vars(node, archive_vars, archive_contexts,
                       tar_modules, zip_modules, tar_open_names, zip_ctor_names):
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
        kind = None
        if _call_is_tar_open(node.value, tar_modules, tar_open_names):
            kind = 'tar'
        elif _call_is_zip_open(node.value, zip_modules, zip_ctor_names):
            kind = 'zip'
        if kind:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    archive_vars[target.id] = kind
    if isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if not isinstance(item.context_expr, ast.Call) or not isinstance(item.optional_vars, ast.Name):
                continue
            if _call_is_tar_open(item.context_expr, tar_modules, tar_open_names):
                archive_contexts.append((item.optional_vars.id, 'tar', node.lineno, getattr(node, 'end_lineno', node.lineno)))
            elif _call_is_zip_open(item.context_expr, zip_modules, zip_ctor_names):
                archive_contexts.append((item.optional_vars.id, 'zip', node.lineno, getattr(node, 'end_lineno', node.lineno)))


def _extraction_kind(call, archive_vars, archive_contexts,
                     tar_modules, zip_modules, tar_open_names, zip_ctor_names,
                     saw_archive_import):
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr not in {'extract', 'extractall'}:
        return None
    owner = func.value
    if isinstance(owner, ast.Name):
        for name, kind, start_line, end_line in reversed(archive_contexts):
            if name == owner.id and start_line <= call.lineno <= end_line:
                return kind
        if owner.id in archive_vars:
            return archive_vars[owner.id]
    if isinstance(owner, ast.Call):
        if _call_is_tar_open(owner, tar_modules, tar_open_names):
            return 'tar'
        if _call_is_zip_open(owner, zip_modules, zip_ctor_names):
            return 'zip'
    if func.attr == 'extractall':
        return 'unknown' if saw_archive_import else None
    return None


def _keyword_value(call, key):
    for keyword in call.keywords:
        if keyword.arg == key:
            return keyword.value
    return None


def _constant_string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _is_safe_tar_filter(node):
    literal = _constant_string(node)
    if literal == 'data':
        return True
    name = _call_name(node)
    return name in {'data_filter', 'tarfile.data_filter'}


def _has_safe_archive_context(kind, call, lines):
    method = call.func.attr if isinstance(call.func, ast.Attribute) else ''
    if kind == 'tar' and method == 'extractall':
        filter_value = _keyword_value(call, 'filter')
        if filter_value is not None and _is_safe_tar_filter(filter_value):
            return True
    if method == 'extract' or _keyword_value(call, 'members') is not None:
        context = '\n'.join(line.split('#', 1)[0] for line in lines[max(0, call.lineno - 16):call.lineno])
        if SAFE_CONTEXT_RE.search(context):
            return True
    return False


def _has_ignore(lines, line_no):
    idx = line_no - 1
    return (
        0 <= idx < len(lines) and 'ubs:ignore' in lines[idx]
    ) or (
        0 <= idx - 1 < len(lines) and 'ubs:ignore' in lines[idx - 1]
    )


def find(files: Sequence[Path]) -> Iterable[tuple[Path, int, int, str]]:
    for path in files:
        if path.suffix.lower() not in {'.py', '.pyi'}:
            continue
        try:
            text = path.read_text(encoding='utf-8')
            tree = ast.parse(text, filename=str(path))
        except Exception:
            continue
        lines = text.splitlines()
        tar_modules = {'tarfile'}
        zip_modules = {'zipfile'}
        tar_open_names = set()
        zip_ctor_names = {'ZipFile'}
        saw_archive_import = False
        archive_vars = {}
        archive_contexts = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == 'tarfile':
                        tar_modules.add(alias.asname or alias.name)
                        saw_archive_import = True
                    elif alias.name == 'zipfile':
                        zip_modules.add(alias.asname or alias.name)
                        saw_archive_import = True
            elif isinstance(node, ast.ImportFrom):
                if node.module == 'tarfile':
                    saw_archive_import = True
                    for alias in node.names:
                        if alias.name == 'open':
                            tar_open_names.add(alias.asname or alias.name)
                elif node.module == 'zipfile':
                    saw_archive_import = True
                    for alias in node.names:
                        if alias.name == 'ZipFile':
                            zip_ctor_names.add(alias.asname or alias.name)

        for node in ast.walk(tree):
            _mark_archive_vars(node, archive_vars, archive_contexts,
                               tar_modules, zip_modules, tar_open_names, zip_ctor_names)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not hasattr(node, 'lineno'):
                continue
            if _has_ignore(lines, node.lineno):
                continue
            kind = _extraction_kind(node, archive_vars, archive_contexts,
                                    tar_modules, zip_modules, tar_open_names,
                                    zip_ctor_names, saw_archive_import)
            if kind is None or _has_safe_archive_context(kind, node, lines):
                continue
            idx = node.lineno - 1
            code = lines[idx].strip()[:240] if 0 <= idx < len(lines) else ''
            yield path, node.lineno, 1, code
