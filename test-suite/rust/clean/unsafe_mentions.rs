#![allow(dead_code)]

/// Documentation can discuss `std::mem::transmute(bytes)` and
/// `std::mem::zeroed::<T>()` without invoking either API.
fn documentation_mentions_are_not_code() -> &'static str {
    "core::hint::unreachable_unchecked() and value.unwrap_unchecked() are text here"
}

fn safe_zeroed_constructor_name() -> PageData {
    PageData::zeroed()
}

struct PageData;

impl PageData {
    fn zeroed() -> Self {
        Self
    }
}
