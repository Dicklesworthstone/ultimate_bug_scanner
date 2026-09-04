//! GH #91 suppression fixture (bead A7) for the Rust module, twin of
//! suppression_buggy_nomarkers.rs (identical buggy code, no markers).
//! Every native rust finding below (the path:line code samples printed by
//! the module: parse().unwrap()/expect() panics, unsafe blocks, raw mutex
//! lock handling) carries an ubs:ignore marker in one of the documented
//! arrangements, so `./ubs test-suite/rust/suppression/suppression_buggy.rs`
//! must report zero findings, while the nomarkers twin reproduces them.

use std::sync::{Arc, Mutex};

// Arrangement 1: previous-line marker.
fn parse_prev_line(raw: &str) -> i32 {
    // ubs:ignore -- fixture: marker on the line immediately above the finding
    let parsed: i32 = raw.parse().unwrap();
    parsed
}

// Arrangement 2: trailing marker on the flagged line itself.
fn unsafe_trailing(ptr: *const u8) -> u8 {
    let value = unsafe { *ptr }; // ubs:ignore -- fixture: trailing marker
    value
}

// Arrangement 3: multi-line statement, marker on a continuation line.
fn clamp_multiline(raw: &str, fallback: i32) -> i32 {
    let parsed: i32 = raw.parse().unwrap().max(
        fallback, // ubs:ignore -- fixture: marker on a physical line of a multi-line statement
    );
    parsed
}

// Arrangement 4: formatter-relocated marker on the first line inside a block.
fn relocated_in_block(flag: bool, raw: &str) -> i32 {
    if flag { let scaled: i32 = raw.parse().unwrap();
        // ubs:ignore -- fixture: formatter moved the marker inside the block
    }
    0
}

// Arrangement 5: rule-scoped markers (ubs:ignore[rule]). The rust module's
// code-sample lines carry no rule id, so these suppress through the runner's
// same-line/previous-line path.
fn poisoned_lock(shared: &Arc<Mutex<u32>>) -> u32 {
    // ubs:ignore[rs.mutex-lock-unwrap] -- fixture: rule-scoped marker above the finding
    let mut guard = shared.lock().unwrap();
    *guard += 1;
    // ubs:ignore[rs.mutex-lock-expect] -- fixture: rule-scoped marker above the finding
    let again = shared.lock().expect("poisoned mutex");
    *again
}

fn rule_scoped_trailing(raw: &str) -> i32 {
    let flagged: i32 = raw.parse().unwrap(); // ubs:ignore[rs.parse-unwrap] -- fixture: rule-scoped trailing marker
    flagged
}
