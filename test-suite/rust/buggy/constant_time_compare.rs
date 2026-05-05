pub struct User {
    pub reset_token: String,
    pub api_key: String,
}

pub struct Request {
    pub authorization: String,
    pub csrf_token: String,
}

pub fn verify_webhook_signature(provided_signature: &str, expected_signature: &str) -> bool {
    provided_signature == expected_signature
}

pub fn verify_api_key(request_api_key: &str, stored_api_key: &str) -> bool {
    if request_api_key != stored_api_key {
        return false;
    }
    true
}

pub fn verify_csrf(req: &Request, session_csrf_token: &str) -> bool {
    req.csrf_token == session_csrf_token
}

pub fn verify_reset_token(token: &str, user: &User) -> bool {
    token == user.reset_token
}

pub fn verify_bearer_token(req: &Request, expected_token: &str) -> bool {
    req.authorization == expected_token
}

pub fn reject_wrong_reset_token(token: &str, user: &User) -> bool {
    token != user.reset_token
}

pub fn verify_signature_inline(signature: &str, expected_signature: &str) -> bool {
    signature == expected_signature
}

pub fn verify_reset_token_after_shape_check(token: &str, expected_reset_token: &str) -> bool {
    token.len() == 64 && token == expected_reset_token
}
