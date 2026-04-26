#![allow(dead_code)]

/// Documentation can discuss `std::mem::transmute(bytes)` and
/// `std::mem::zeroed::<T>()` without invoking either API.
/// It can also mention `CStr::from_bytes_with_nul_unchecked(bytes)`,
/// `values.get_unchecked(index)`, `str::from_utf8_unchecked(bytes)`,
/// `slice::from_raw_parts(ptr, len)`, and `unsafe impl Send for Handle {}`.
/// Text may show `impl Drop for Bomb { fn drop(&mut self) { panic!("boom") } }`
/// or `self.detail.expect("boom")` without creating executable Drop code.
fn documentation_mentions_are_not_code() -> &'static str {
    "core::hint::unreachable_unchecked(), value.unwrap_unchecked(), \
     String::from_utf8_unchecked(bytes), panic!(), expect(), \
     and unsafe impl Sync for Handle {} are text here"
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
