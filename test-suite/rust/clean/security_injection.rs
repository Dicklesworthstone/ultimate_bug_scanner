use std::process::Command;

fn safe_command(user: &str) {
    Command::new("ls").arg(user).status().unwrap();
}

fn main() {
    let user = "docs";
    safe_command(user);
}
