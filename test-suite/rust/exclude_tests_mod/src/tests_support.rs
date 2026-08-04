// Fixture for GH #80: this file is referenced ONLY by the #[cfg(test)]-gated
// `mod tests_support;` declaration in lib.rs, so it is test-only code even
// though it contains no #[cfg(test)] marker itself. With --exclude-tests the
// unwrap and panic! below must not be counted; by default they must be.

pub fn helper_value() -> u32 {
    let missing: Option<u32> = None;
    missing.unwrap()
}

pub fn explode() {
    panic!("test-only panic");
}
