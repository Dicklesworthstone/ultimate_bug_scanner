use std::path::{Path, PathBuf};
use std::process::Command;

fn insecure_command(user: &str) {
    Command::new("sh").arg("-c").arg(user).status().unwrap();
}

fn insecure_login_shell(user: &str) {
    Command::new("bash").args(["-lc", user]).status().unwrap();
}

fn insecure_windows_shell(user: &str) {
    Command::new("cmd").args(&["/C", user]).status().unwrap();
}

fn read_user_path(root: &Path, user_path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(root.join(user_path))
}

fn push_uploaded_file(mut upload_dir: PathBuf, file_name: &str) -> PathBuf {
    upload_dir.push(file_name);
    upload_dir
}

fn main() {
    let user = "rm -rf /";
    insecure_command(user);
    insecure_login_shell(user);
    insecure_windows_shell(user);
    let _ = read_user_path(Path::new("/srv/data"), "../../etc/passwd");
    let _ = push_uploaded_file(PathBuf::from("/srv/uploads"), "../shell.php");
    println!("{:?}", std::env::var("API_KEY").unwrap_or("sk_live_123".into()));
}
