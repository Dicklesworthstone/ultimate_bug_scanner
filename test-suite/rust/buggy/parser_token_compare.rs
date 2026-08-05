// GH #85 positive control: qualified security vocabulary must still be
// detected by the constant-time comparison detector even after the
// parser-vocabulary tightening in the paired clean fixture.

pub fn verify_session_token(session_token: &str, expected_session_token: &str) -> bool {
    session_token == expected_session_token
}

pub fn verify_api_key(request_api_key: &str, stored_api_key: &str) -> bool {
    request_api_key == stored_api_key
}

pub fn tainted_parser_style_alias(auth_token: &str, expected: &str) -> bool {
    let candidate = auth_token;
    candidate == expected
}
