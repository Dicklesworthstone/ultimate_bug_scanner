// GH #85 regression fixture: ordinary parser/domain vocabulary must not be
// treated as secret material by the constant-time comparison detector.
// Shaped after the NAIC bond-holdings parser false positive, where a parser
// `token` iterator tainted `candidate == "BR2"` (a document-layout marker).

pub fn find_layout_marker(line: &str) -> bool {
    let mut token = line.split_whitespace();
    let candidate = token.next().unwrap_or("");
    candidate == "BR2"
}

pub fn is_page_break(token: &str) -> bool {
    token == "PAGE_BREAK" || token == "FF"
}

pub fn session_matches(session_id: &str, expected: &str) -> bool {
    session_id == expected
}

pub fn signature_format_is_detached(signature_format: &str) -> bool {
    signature_format == "detached"
}

pub fn credential_kind_is_certificate(credential_type: &str) -> bool {
    credential_type == "certificate"
}

pub fn jwt_header_is_jose(jwt_header: &str) -> bool {
    jwt_header == "JOSE"
}

pub fn map_key_present(key: &str, keys: &[String]) -> bool {
    keys.iter().any(|entry| entry == key)
}

// A security-sensitive assignment in one function must not taint a reused
// local name in an unrelated function.
pub fn load_recovery_issue(title: &str) -> String {
    let issue = format!("secret: {title}");
    issue
}

pub struct PublicIssue {
    pub title: String,
}

pub fn public_issue_title_matches(issue: &PublicIssue) -> bool {
    issue.title == "Modified"
}
