#![allow(dead_code)]

use std::ffi::CStr;
use std::slice;
use std::str;

struct RawHandle(*mut u8);

unsafe impl Send for RawHandle {}
unsafe impl Sync for RawHandle {}

fn reinterpret(bytes: [u8; 8]) -> u64 {
    unsafe { std::mem::transmute(bytes) }
}

fn make_zeroed_reference() -> &'static u8 {
    unsafe { std::mem::zeroed::<&'static u8>() }
}

fn impossible_branch(flag: bool) -> usize {
    if flag {
        1
    } else {
        unsafe { std::hint::unreachable_unchecked() }
    }
}

fn unchecked_cstr(bytes: &[u8]) -> &CStr {
    unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
}

fn unchecked_index(values: &[u8], index: usize) -> u8 {
    unsafe { *values.get_unchecked(index) }
}

fn unchecked_index_mut(values: &mut [u8], index: usize) -> &mut u8 {
    unsafe { values.get_unchecked_mut(index) }
}

fn unchecked_utf8(bytes: &[u8]) -> &str {
    unsafe { str::from_utf8_unchecked(bytes) }
}

fn unchecked_owned_utf8(bytes: Vec<u8>) -> String {
    unsafe { String::from_utf8_unchecked(bytes) }
}

fn raw_parts(ptr: *const u8, len: usize) -> &'static [u8] {
    unsafe { slice::from_raw_parts(ptr, len) }
}

fn raw_parts_mut(ptr: *mut u8, len: usize) -> &'static mut [u8] {
    unsafe { slice::from_raw_parts_mut(ptr, len) }
}

struct PanicsDuringDrop {
    detail: Option<String>,
}

impl Drop for PanicsDuringDrop {
    fn drop(&mut self) {
        let detail = self.detail.as_ref().expect("drop detail should exist");
        panic!("failed while dropping {detail}");
    }
}
