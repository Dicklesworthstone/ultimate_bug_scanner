// Fixture for GH #71: --emit-findings-json must escape ALL JSON control
// characters, not just quote/backslash. The panic! line below embeds raw
// ESC (0x1b), form-feed (0x0c), and SOH (0x01) bytes; the println!/format!
// lines carry real tab characters, escaped tabs, backslashes, and quotes.

pub fn shout(value: u32) {
    panic!("control chars ahead: [31mred[0m form-feed soh");
}

pub fn print_things(value: u32) {
    println!("{}", value);
    println!("tab	literal and escaped \t plus C:\\logs\\out \"quoted\"");
    let rendered = format!("{}	value with a real tab and backslash \\", value);
    println!("{}", rendered);
}
