use std::process::Command;

fn insecure_command(user: &str) {
    Command::new("sh").arg("-c").arg(user).status().unwrap();
}

fn main() {
    let user = "rm -rf /";
    insecure_command(user);
    println!("{:?}", std::env::var("API_KEY").unwrap_or("sk_live_123".into()));
}
