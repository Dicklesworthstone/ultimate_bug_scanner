use std::path::{Path, PathBuf};
use std::process::Command;

fn safe_command(user: &str) {
    Command::new("ls").arg(user).status().unwrap();
}

fn safe_args_command(user: &str) {
    let _ = Command::new("grep").args(["--", user, "Cargo.toml"]).status();
}

fn safe_constant_asset(root: &Path) -> PathBuf {
    root.join("index.html")
}

fn main() {
    let user = "docs";
    safe_command(user);
    safe_args_command(user);
    let _asset = safe_constant_asset(Path::new("/srv/www"));
}
