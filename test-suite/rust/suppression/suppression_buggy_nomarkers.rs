//! GH #91 suppression fixture (bead A7) for the Rust module, twin of
//! suppression_buggy.rs: identical buggy code with every ubs:ignore marker
//! removed, so a scan of this file must reproduce the native rust findings
//! (parse().unwrap()/expect() panics, unsafe blocks, raw mutex lock
//! handling) that the markered twin suppresses.

use std::sync::{Arc, Mutex};

// Arrangement 1: previous-line marker position.
fn parse_prev_line(raw: &str) -> i32 {
    let parsed: i32 = raw.parse().unwrap();
    parsed
}

// Arrangement 2: trailing marker position on the flagged line itself.
fn unsafe_trailing(ptr: *const u8) -> u8 {
    let value = unsafe { *ptr };
    value
}

// Arrangement 3: multi-line statement, marker position on a continuation line.
fn clamp_multiline(raw: &str, fallback: i32) -> i32 {
    let parsed: i32 = raw.parse().unwrap().max(
        fallback,
    );
    parsed
}

// Arrangement 4: formatter-relocated marker position, first line inside a block.
fn relocated_in_block(flag: bool, raw: &str) -> i32 {
    if flag { let scaled: i32 = raw.parse().unwrap();
    }
    0
}

// Arrangement 5: rule-scoped marker positions (bracketed rule form). The rust
// module's code-sample lines carry no rule id, so the markered twin suppresses
// these through the runner's same-line/previous-line path.
fn poisoned_lock(shared: &Arc<Mutex<u32>>) -> u32 {
    let mut guard = shared.lock().unwrap();
    *guard += 1;
    let again = shared.lock().expect("poisoned mutex");
    *again
}

fn rule_scoped_trailing(raw: &str) -> i32 {
    let flagged: i32 = raw.parse().unwrap();
    flagged
}
