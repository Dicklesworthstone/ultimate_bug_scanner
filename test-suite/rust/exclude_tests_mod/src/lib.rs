// Fixture for GH #80: --exclude-tests must drop (a) AST-backed matches at or
// below the #[cfg(test)] boundary and (b) files reachable only through
// #[cfg(test)]-gated `mod` declarations (see tests_support.rs), while the
// production findings above the boundary keep counting.

use std::sync::Mutex;

pub fn read_counter(m: &Mutex<u32>) -> u32 {
    let guard = m.lock().unwrap(); // production finding: stays with --exclude-tests
    *guard
}

pub fn fail_fast() {
    panic!("production panic: stays with --exclude-tests");
}

#[cfg(test)]
mod tests_support;

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    #[test]
    fn counts() {
        let m = Mutex::new(41u32);
        let sneaky = m.lock().unwrap(); // test-only: gone with --exclude-tests
        assert_eq!(*sneaky + 1, 42);
    }
}
