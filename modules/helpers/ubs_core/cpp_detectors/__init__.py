"""ubs_core.cpp_detectors — ports of the legacy ubs-cpp.sh detectors.

Every module exposes the shared protocol (see ubs_core.cpp_scan.run_detectors):
    RULE_ID / CATEGORY / TITLE / SEVERITY / DESCRIPTION + find(files), or a
    RULES tuple for multi-rule modules.

Detection logic is ported verbatim from the legacy heredocs / rg pipelines
(same regex tables, same statement windows, same `ubs:ignore` handling); the
heredocs' self-walking iter_files is replaced by iteration over the v2 file
list, which ubs_list_files scopes identically for the manifest fixtures.
"""
