// Fixture for GH #70: production code outside any excluded directory.
// This file must always be scanned; the findings that matter for the
// regression live in ../vendor_tools/nested/src/leaky.rs, which the
// manifest case excludes via --exclude=vendor_tools.

pub fn add(a: u32, b: u32) -> Option<u32> {
    a.checked_add(b)
}
