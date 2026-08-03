// Fixture for GH #69 / #71: --emit-findings-json must JSON-escape source samples.
//
// Every line below produces a finding whose *sample* is the raw source line.
// The samples deliberately carry the three characters that break a naive
// emitter: a double quote, a backslash, and an escape sequence.

pub fn fail() {
    panic!("quoted sample");
}

pub fn shout(v: u32) {
    println!("{}", v);
    println!("path C:\\tmp\\log \"quoted\" \t tabbed");
}
