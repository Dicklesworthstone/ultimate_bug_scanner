#![allow(dead_code)]

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
