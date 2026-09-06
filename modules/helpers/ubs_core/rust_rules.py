"""ubs_core.rust_rules — consolidated ast-grep rule generation for Rust (bead 0xjg.7).

The legacy module (modules/ubs-rust.sh, contract v1) counts its AST-backed
checks through ~140 ad-hoc ``ast-grep run --pattern`` spawns (``ast_search`` /
``count_ast_or_rg``) and carries a separate SARIF-only rule pack
(``write_ast_rules``) that never joins the text-mode counters.

``generate(rule_dir)`` writes the counter-relevant ad-hoc patterns as ONE
rule-per-file sgconfig pack (the PortGolang generator precedent, bead 0xjg.6):

    <rule_dir>/<slug>.yml        one rule per legacy pattern, id rust.ast.<slug>
    <rule_dir>/sgconfig-rust.yml single-grammar config — one ``scan -c`` per
                                 400-path batch instead of one spawn per check
    <rule_dir>/manifest.json     rule id -> {pattern, category, check}

``AST_PATTERNS`` below preserves the legacy pattern texts verbatim (byte
identity matters: ast-grep matching is pattern-exact). A pattern this
ast-grep build rejects would have produced zero ``run --pattern`` output in
legacy too (the spawn failed, the count stayed 0) — such rules are kept out
of the sgconfig in ``_UNPARSEABLE_RULES`` so one bad stem cannot sink the
consolidated scan, exactly like the go pack.
"""
from __future__ import annotations

import json
from pathlib import Path

__all__ = ["AST_PATTERNS", "UNPARSEABLE_RULES", "generate"]


def _p(category: int, check: str, slug: str, pattern: str) -> tuple[int, str, str, str]:
    return (category, check, slug, pattern)


# (category, check-slug, rule-slug, ast-grep pattern) — legacy call order.
AST_PATTERNS: tuple[tuple[int, str, str, str], ...] = (
    # Category 1 — ownership & error handling (ubs-rust.sh 8352-8431)
    _p(1, "unwrap_expect", "unwrap", "$X.unwrap()"),
    _p(1, "unwrap_expect", "expect", "$X.expect($MSG)"),
    _p(1, "panic_macro", "panic", "panic!($$$ARGS)"),
    _p(1, "unreachable_macro", "unreachable", "unreachable!($$$ARGS)"),
    _p(1, "todo_macro", "todo", "todo!($$$ARGS)"),
    _p(1, "unimplemented_macro", "unimplemented", "unimplemented!($$$ARGS)"),
    _p(1, "dbg_macro", "dbg", "dbg!($$$ARGS)"),
    _p(1, "println_macro", "println", "println!($$$ARGS)"),
    _p(1, "eprintln_macro", "eprintln", "eprintln!($$$ARGS)"),
    # Category 2 — unsafe & memory operations (8436-8544)
    _p(2, "unsafe_blocks", "unsafe_block", "unsafe { $$$BODY }"),
    _p(2, "transmute", "transmute_std", "std::mem::transmute($X)"),
    _p(2, "transmute", "transmute_mem", "mem::transmute($X)"),
    _p(2, "transmute", "transmute_bare", "transmute($X)"),
    _p(2, "uninit", "uninit_std", "std::mem::uninitialized::<$T>()"),
    _p(2, "uninit", "uninit_mem", "mem::uninitialized::<$T>()"),
    _p(2, "zeroed", "zeroed_std_t", "std::mem::zeroed::<$T>()"),
    _p(2, "zeroed", "zeroed_mem_t", "mem::zeroed::<$T>()"),
    _p(2, "zeroed", "zeroed_std", "std::mem::zeroed()"),
    _p(2, "zeroed", "zeroed_mem", "mem::zeroed()"),
    _p(2, "zeroed", "zeroed_bare", "zeroed()"),
    _p(2, "assume_init", "assume_init", "$X.assume_init()"),
    _p(2, "forget", "forget_std", "std::mem::forget($X)"),
    _p(2, "forget", "forget_mem", "mem::forget($X)"),
    _p(2, "cstr_unchecked", "cstr_std", "std::ffi::CStr::from_bytes_with_nul_unchecked($BYTES)"),
    _p(2, "cstr_unchecked", "cstr_bare", "CStr::from_bytes_with_nul_unchecked($BYTES)"),
    _p(2, "get_unchecked", "get_unchecked", "$S.get_unchecked($I)"),
    _p(2, "get_unchecked", "get_unchecked_mut", "$S.get_unchecked_mut($I)"),
    _p(2, "utf8_unchecked", "utf8_std", "std::str::from_utf8_unchecked($BYTES)"),
    _p(2, "utf8_unchecked", "utf8_str", "str::from_utf8_unchecked($BYTES)"),
    _p(2, "utf8_unchecked", "utf8_string_std", "std::string::String::from_utf8_unchecked($BYTES)"),
    _p(2, "utf8_unchecked", "utf8_string", "String::from_utf8_unchecked($BYTES)"),
    _p(2, "raw_parts", "raw_parts_std", "std::slice::from_raw_parts($PTR, $LEN)"),
    _p(2, "raw_parts", "raw_parts_std_mut", "std::slice::from_raw_parts_mut($PTR, $LEN)"),
    _p(2, "raw_parts", "raw_parts_slice", "slice::from_raw_parts($PTR, $LEN)"),
    _p(2, "raw_parts", "raw_parts_slice_mut", "slice::from_raw_parts_mut($PTR, $LEN)"),
    _p(2, "unsafe_impl", "unsafe_impl_send", "unsafe impl Send for $T { $$$BODY }"),
    _p(2, "unsafe_impl", "unsafe_impl_sync", "unsafe impl Sync for $T { $$$BODY }"),
    # Category 3 — concurrency & async (8549-8624)
    _p(3, "arc_mutex", "arc_mutex", "Arc<Mutex<$T>>"),
    _p(3, "rc_refcell", "rc_refcell", "Rc<RefCell<$T>>"),
    _p(3, "lock_unwrap", "lock_unwrap", "$M.lock().unwrap()"),
    _p(3, "lock_unwrap", "lock_expect", "$M.lock().expect($MSG)"),
    _p(3, "await_in_loop", "await_in_for", "for $P in $I { $$ $F.await $$ }"),
    # Category 5 — collections & iterators (8649-8693)
    _p(5, "clone_any", "clone", "$X.clone()"),
    _p(5, "collect_vec", "collect_vec", "$I.collect::<Vec<$T>>()"),
    _p(5, "nth0", "nth0", "$I.nth(0)"),
    # Category 6 — string & allocation smells (8698-8720)
    _p(6, "to_owned_to_string", "to_owned_to_string", "$X.to_owned().to_string()"),
    # Category 8 — security (8742-9203)
    _p(8, "weak_hash", "md5", "md5::$F($$)"),
    _p(8, "weak_hash", "sha1", "sha1::$F($$)"),
    _p(8, "tls_insecure", "tls_certs", "reqwest::ClientBuilder::new().danger_accept_invalid_certs(true)"),
    _p(8, "tls_insecure", "tls_hostnames", "reqwest::ClientBuilder::new().danger_accept_invalid_hostnames(true)"),
    _p(8, "shell_command", "shell_std_arg_c", "std::process::Command::new($S).arg(\"-c\").arg($CMD)"),
    _p(8, "shell_command", "shell_arg_c", "Command::new($S).arg(\"-c\").arg($CMD)"),
    _p(8, "shell_command", "shell_std_arg_lc", "std::process::Command::new($S).arg(\"-lc\").arg($CMD)"),
    _p(8, "shell_command", "shell_arg_lc", "Command::new($S).arg(\"-lc\").arg($CMD)"),
    _p(8, "shell_command", "shell_std_arg_wc", "std::process::Command::new($S).arg(\"/C\").arg($CMD)"),
    _p(8, "shell_command", "shell_arg_wc", "Command::new($S).arg(\"/C\").arg($CMD)"),
    _p(8, "shell_command", "shell_std_arg_wcl", "std::process::Command::new($S).arg(\"/c\").arg($CMD)"),
    _p(8, "shell_command", "shell_arg_wcl", "Command::new($S).arg(\"/c\").arg($CMD)"),
    _p(8, "shell_command", "shell_std_args_c", "std::process::Command::new($S).args([\"-c\", $CMD])"),
    _p(8, "shell_command", "shell_args_c", "Command::new($S).args([\"-c\", $CMD])"),
    _p(8, "shell_command", "shell_std_args_lc", "std::process::Command::new($S).args([\"-lc\", $CMD])"),
    _p(8, "shell_command", "shell_args_lc", "Command::new($S).args([\"-lc\", $CMD])"),
    _p(8, "shell_command", "shell_std_args_wc", "std::process::Command::new($S).args([\"/C\", $CMD])"),
    _p(8, "shell_command", "shell_args_wc", "Command::new($S).args([\"/C\", $CMD])"),
    _p(8, "shell_command", "shell_std_args_wcl", "std::process::Command::new($S).args([\"/c\", $CMD])"),
    _p(8, "shell_command", "shell_args_wcl", "Command::new($S).args([\"/c\", $CMD])"),
    _p(8, "shell_command", "shell_std_argsref_c", "std::process::Command::new($S).args(&[\"-c\", $CMD])"),
    _p(8, "shell_command", "shell_argsref_c", "Command::new($S).args(&[\"-c\", $CMD])"),
    _p(8, "shell_command", "shell_std_argsref_lc", "std::process::Command::new($S).args(&[\"-lc\", $CMD])"),
    _p(8, "shell_command", "shell_argsref_lc", "Command::new($S).args(&[\"-lc\", $CMD])"),
    _p(8, "shell_command", "shell_std_argsref_wc", "std::process::Command::new($S).args(&[\"/C\", $CMD])"),
    _p(8, "shell_command", "shell_argsref_wc", "Command::new($S).args(&[\"/C\", $CMD])"),
    _p(8, "shell_command", "shell_std_argsref_wcl", "std::process::Command::new($S).args(&[\"/c\", $CMD])"),
    _p(8, "shell_command", "shell_argsref_wcl", "Command::new($S).args(&[\"/c\", $CMD])"),
    _p(8, "http_url", "http_url", "\"http://$REST\""),
    # Category 20 — async locking across await (9517-9544)
    _p(20, "std_lock_async", "std_lock_async_lock", "async fn $N($$) { $$ $M.lock() $$ }"),
    _p(20, "std_lock_async", "std_lock_async_read", "async fn $N($$) { $$ $M.read() $$ }"),
    _p(20, "std_lock_async", "std_lock_async_write", "async fn $N($$) { $$ $M.write() $$ }"),
    _p(20, "std_guard_await", "std_guard_await_unwrap", "async fn $N($$) { $$ let $G = $M.lock().unwrap(); $$ $X.await $$ }"),
    _p(20, "std_guard_await", "std_guard_await_expect", "async fn $N($$) { $$ let $G = $M.lock().expect($MSG); $$ $X.await $$ }"),
    _p(20, "tokio_guard_await", "tokio_guard_lock", "async fn $N($$) { $$ let $G = $M.lock().await; $$ $X.await $$ }"),
    _p(20, "tokio_guard_await", "tokio_guard_read", "async fn $N($$) { $$ let $G = $M.read().await; $$ $X.await $$ }"),
    _p(20, "tokio_guard_await", "tokio_guard_write", "async fn $N($$) { $$ let $G = $M.write().await; $$ $X.await $$ }"),
    # Category 21 — panic surfaces (9549-9593)
    _p(21, "assert_macros", "assert", "assert!($$)"),
    _p(21, "assert_macros", "assert_eq", "assert_eq!($$)"),
    _p(21, "assert_macros", "assert_ne", "assert_ne!($$)"),
    _p(21, "unchecked_ub", "unreachable_unchecked_std", "std::hint::unreachable_unchecked()"),
    _p(21, "unchecked_ub", "unreachable_unchecked_core", "core::hint::unreachable_unchecked()"),
    _p(21, "unchecked_ub", "unwrap_unchecked", "$X.unwrap_unchecked()"),
    _p(21, "direct_index", "direct_index", "$X[$I]"),
    # Category 22 — casts & truncation (9598-9664)
    _p(22, "as_casts", "as_u8", "$X as u8"),
    _p(22, "as_casts", "as_u16", "$X as u16"),
    _p(22, "as_casts", "as_u32", "$X as u32"),
    _p(22, "as_casts", "as_u64", "$X as u64"),
    _p(22, "as_casts", "as_usize", "$X as usize"),
    _p(22, "as_casts", "as_i8", "$X as i8"),
    _p(22, "as_casts", "as_i16", "$X as i16"),
    _p(22, "as_casts", "as_i32", "$X as i32"),
    _p(22, "as_casts", "as_i64", "$X as i64"),
    _p(22, "as_casts", "as_isize", "$X as isize"),
    _p(22, "as_casts", "as_f32", "$X as f32"),
    _p(22, "as_casts", "as_f64", "$X as f64"),
    _p(22, "len_count_narrow", "len_as_u8", "$X.len() as u8"),
    _p(22, "len_count_narrow", "len_as_u16", "$X.len() as u16"),
    _p(22, "len_count_narrow", "len_as_u32", "$X.len() as u32"),
    _p(22, "len_count_narrow", "len_as_i8", "$X.len() as i8"),
    _p(22, "len_count_narrow", "len_as_i16", "$X.len() as i16"),
    _p(22, "len_count_narrow", "len_as_i32", "$X.len() as i32"),
    _p(22, "len_count_narrow", "count_as_u8", "$X.count() as u8"),
    _p(22, "len_count_narrow", "count_as_u16", "$X.count() as u16"),
    _p(22, "len_count_narrow", "count_as_u32", "$X.count() as u32"),
    _p(22, "len_count_narrow", "count_as_i8", "$X.count() as i8"),
    _p(22, "len_count_narrow", "count_as_i16", "$X.count() as i16"),
    _p(22, "len_count_narrow", "count_as_i32", "$X.count() as i32"),
    _p(22, "try_into_unwrap", "try_into_unwrap", "$X.try_into().unwrap()"),
    _p(22, "try_into_unwrap", "try_into_expect", "$X.try_into().expect($MSG)"),
    # Category 23 — parsing & validation robustness (9669-9725)
    _p(23, "parse_unwrap", "parse_tf_unwrap", "$S.parse::<$T>().unwrap()"),
    _p(23, "parse_unwrap", "parse_tf_expect", "$S.parse::<$T>().expect($MSG)"),
    _p(23, "parse_unwrap", "parse_unwrap", "$S.parse().unwrap()"),
    _p(23, "parse_unwrap", "parse_expect", "$S.parse().expect($MSG)"),
    _p(23, "serde_unwrap", "serde_json_from_str_unwrap", "serde_json::from_str($S).unwrap()"),
    _p(23, "serde_unwrap", "serde_json_from_str_expect", "serde_json::from_str($S).expect($MSG)"),
    _p(23, "serde_unwrap", "serde_json_from_slice_unwrap", "serde_json::from_slice($S).unwrap()"),
    _p(23, "serde_unwrap", "serde_json_from_slice_expect", "serde_json::from_slice($S).expect($MSG)"),
    _p(23, "serde_unwrap", "serde_json_from_value_unwrap", "serde_json::from_value($S).unwrap()"),
    _p(23, "serde_unwrap", "serde_json_from_value_expect", "serde_json::from_value($S).expect($MSG)"),
    _p(23, "serde_unwrap", "serde_yaml_from_str_unwrap", "serde_yaml::from_str($S).unwrap()"),
    _p(23, "serde_unwrap", "serde_yaml_from_str_expect", "serde_yaml::from_str($S).expect($MSG)"),
    _p(23, "serde_unwrap", "toml_from_str_unwrap", "toml::from_str($S).unwrap()"),
    _p(23, "serde_unwrap", "toml_from_str_expect", "toml::from_str($S).expect($MSG)"),
    _p(23, "env_unwrap", "env_std_var_unwrap", "std::env::var($K).unwrap()"),
    _p(23, "env_unwrap", "env_std_var_expect", "std::env::var($K).expect($MSG)"),
    _p(23, "env_unwrap", "env_var_unwrap", "env::var($K).unwrap()"),
    _p(23, "env_unwrap", "env_var_expect", "env::var($K).expect($MSG)"),
    _p(23, "env_unwrap", "env_std_var_os_unwrap", "std::env::var_os($K).unwrap()"),
    _p(23, "env_unwrap", "env_std_var_os_expect", "std::env::var_os($K).expect($MSG)"),
    _p(23, "env_unwrap", "env_var_os_unwrap", "env::var_os($K).unwrap()"),
    _p(23, "env_unwrap", "env_var_os_expect", "env::var_os($K).expect($MSG)"),
    # Category 24 — perf/DoS hotspots (9730-9778)
    _p(24, "regex_new", "regex_new_full", "regex::Regex::new($RE)"),
    _p(24, "regex_new", "regex_new_bare", "Regex::new($RE)"),
    _p(24, "chars_nth", "chars_nth", "$S.chars().nth($N)"),
    _p(24, "chars_nth", "chars_nth_back", "$S.chars().nth_back($N)"),
)

# Patterns this ast-grep build rejects at load time, probed against
# ast-grep 0.45.3 (2026-09-05): every AST_PATTERNS stem parses except these
# two type-only patterns. Legacy `run --pattern` refused them the same way
# (ERROR-node warning, zero output), so their legacy AST contribution was
# always 0 and the rg side carried the count — excluding them reproduces
# that exactly and keeps one bad stem from aborting the consolidated scan.
UNPARSEABLE_RULES: frozenset[str] = frozenset({
    "arc_mutex",      # Arc<Mutex<$T>>  (type pattern; rg side counts)
    "rc_refcell",     # Rc<RefCell<$T>> (type pattern; rg side counts)
})


def generate(rule_dir: Path) -> dict:
    """Write the consolidated rule pack; return the manifest dict."""
    rule_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, dict] = {}
    rule_files: list[str] = []
    for category, check, slug, pattern in AST_PATTERNS:
        rule_id = f"rust.ast.{slug}"
        if slug in UNPARSEABLE_RULES:
            continue
        filename = f"{slug}.yml"
        # Always double-quote the pattern (YAML flow scalar via json.dumps):
        # patterns embed braces, brackets, quotes and `>` — plain scalars
        # would be ambiguous.
        body = (
            f"id: {rule_id}\n"
            "language: rust\n"
            "rule:\n"
            f"  pattern: {json.dumps(pattern)}\n"
        )
        (rule_dir / filename).write_text(body, encoding="utf-8")
        rule_files.append(filename)
        manifest[rule_id] = {"pattern": pattern, "category": category, "check": check}
    sgconfig = (
        "ruleDirs:\n"
        + "".join(f"  - ./{filename}\n" for filename in rule_files)
    )
    (rule_dir / "sgconfig-rust.yml").write_text(sgconfig, encoding="utf-8")
    (rule_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


if __name__ == "__main__":  # pragma: no cover - manual smoke tool
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".ubs-rust-rules")
    written = generate(target)
    print(f"wrote {len(written)} rules to {target}")
