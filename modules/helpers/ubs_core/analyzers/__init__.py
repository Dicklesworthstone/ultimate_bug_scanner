"""ubs_core.analyzers — analyzer modules registered per language (bead A2).

Registry queries load the modules they need; importing one analyzer's helpers
does not first import every other language. Full registry queries still discover
every module automatically. Unlisted modules are loaded for every language, so
adding an analyzer never requires updating the optimization index below.
"""
from __future__ import annotations

import importlib
import pkgutil


# Only known language-exclusive modules belong here. Shared and new modules
# deliberately fall back to eager loading. The registry independence tests
# compare language-first discovery with complete discovery, including self-tests.
_LANGUAGE_MODULES = {
    "cpp": ("lifecycle_cpp", "narrowing_cpp", "taint_cpp_redirect", "taint_cpp_traversal"),
    "csharp": ("async_handles_csharp", "lifecycle_csharp", "narrowing_csharp",
               "taint_csharp_redirect", "taint_csharp_request", "taint_csharp_sql"),
    "elixir": ("lifecycle_elixir", "narrowing_elixir", "taint_elixir_redirect", "taint_elixir_traversal"),
    "go": ("ctcompare_go", "narrowing_go", "taint_go"),
    "java": ("lifecycle_java", "taint_java_redirect", "taint_java_sql", "taint_java_traversal"),
    "javascript": (
        "async_event_emitter", "async_event_listener", "async_flatmap", "async_foreach",
        "async_jsx_handler", "async_map_awaited", "async_map_ignored", "async_predicates",
        "async_promise_all_foreach", "async_promise_all_map", "async_promise_executor",
        "async_react_effect", "async_reduce", "async_sort_comparator", "async_timer",
        "ctcompare_js", "guards_js", "sec_archive_entry", "sec_cookies", "sec_cors",
        "sec_dangerous_html", "sec_fetch_abort", "sec_hardcoded_secrets", "sec_header_injection",
        "sec_host_header", "sec_jsx_target_blank", "sec_jwt", "sec_message_origin",
        "sec_open_redirect", "sec_path_traversal", "sec_post_message", "sec_prototype_pollution",
        "sec_request_body", "sec_request_regex", "sec_reverse_proxy", "sec_sql_injection",
        "sec_ssrf_fetch", "sec_tls", "sec_weak_random", "spec_block_function", "spec_division",
        "spec_hooks", "spec_switch_fallthrough", "spec_typeof", "taint_js",
    ),
    "kotlin": ("coroutines_kotlin", "lifecycle_kotlin", "narrowing_kotlin", "taint_kotlin_sql"),
    "php": ("taint_php",),
    "python": ("ctcompare_py", "guards_py", "lifecycle_py", "narrowing_py", "taint_py"),
    "ruby": ("guards_ruby", "lifecycle_ruby", "narrowing_ruby", "taint_ruby_traversal", "taint_ruby_url"),
    "rust": ("cfg_test_only_rust", "ctcompare_rust", "narrowing_rust", "taint_rust"),
    "swift": ("lifecycle_swift", "narrowing_swift", "regex_swift", "taint_swift_redirect", "taint_swift_traversal"),
}
_MODULE_LANGUAGE = {module: lang for lang, modules in _LANGUAGE_MODULES.items() for module in modules}


def load(lang: str | None = None) -> None:
    """Discover all analyzers, or defer known modules exclusive to other languages.

    Imports retain their normal dependency resolution and errors. In particular,
    a selected analyzer can import helpers from any otherwise deferred module.
    """
    # Kotlin's JVM adapters import Java traversal and SQL helpers. Discover Java
    # in its normal order first so a later complete query retains that order.
    if lang == "kotlin":
        load("java")
    for module_info in pkgutil.iter_modules(__path__):
        if module_info.name.startswith("_"):
            continue
        owner = _MODULE_LANGUAGE.get(module_info.name)
        if lang is not None and owner is not None and owner != lang:
            continue
        importlib.import_module(f"{__name__}.{module_info.name}")
