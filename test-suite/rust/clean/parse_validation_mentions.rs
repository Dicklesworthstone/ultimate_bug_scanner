fn documentation_mentions_only() -> &'static str {
    r#"
    Examples in prose should not trigger parser robustness warnings:
    raw.parse::<usize>().unwrap()
    serde_json::from_str(raw).unwrap()
    std::env::var("APP_MODE").expect("configured")
    payload.len() as u8
    values.iter().count() as u16
    panic!("docs only")
    todo!()
    dbg!(value)
    println!("debug docs")
    "#
}

fn parse_with_context(raw: &str) -> Result<u16, std::num::ParseIntError> {
    raw.parse::<u16>()
}

fn parse_inferred_with_context(raw: &str) -> Result<u16, std::num::ParseIntError> {
    raw.parse()
}

fn read_mode() -> String {
    std::env::var("APP_MODE").unwrap_or_else(|_| "development".to_string())
}

fn bounded_packet_len(packet: &[u8]) -> u8 {
    packet.len() as u8 // ubs:ignore - fixture proves justified AST matches stay suppressed.
}

fn notes() {
    // env::var("SECRET").unwrap() should stay documentation, not executable code.
    // payload.len() as u8 should stay documentation, not a truncation warning.
    // panic!(), todo!(), dbg!(), and println!() should stay documentation too.
    let _ = documentation_mentions_only();
    let _ = bounded_packet_len(b"ok");
}
