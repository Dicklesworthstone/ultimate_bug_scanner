// Fixture for GH #70: this file lives in a directory the manifest case
// excludes with --exclude=vendor_tools. Helper scanners (hardcoded-secret
// walker, panic scan, etc.) must NOT report findings from here when the
// exclusion is active, and the displayed file count must not include it.

pub fn connect() -> String {
    let api_key = "sk-live-0123456789abcdef0123456789abcdef";
    let password = std::env::var("DB_PASSWORD").unwrap_or("hunter2secret".to_string());
    panic!("excluded panic: {}{}", api_key, password);
}
