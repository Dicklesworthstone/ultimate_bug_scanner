"""ubs_core.rust_detectors — legacy heredoc detector ports for the Rust module (bead 0xjg.7).

Each module ports one `python3 - "$PROJECT_DIR" <<'PY'` heredoc from
modules/ubs-rust.sh verbatim (see the module docstrings for the source line
ranges). Protocol: module-level RULE_ID / CATEGORY / TITLE / SEVERITY /
DESCRIPTION plus `find(files)` yielding (path, line, col, code); mode-based
detectors (async_context, loop_context) expose MODES and `find(files, mode)`.
"""
