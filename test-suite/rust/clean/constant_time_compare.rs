use subtle::ConstantTimeEq;

pub fn timing_safe_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.ct_eq(right).into()
}

pub fn verify_webhook_signature(provided_signature: &[u8], expected_signature: &[u8]) -> bool {
    provided_signature.ct_eq(expected_signature).into()
}

pub fn verify_api_key(request_api_key: &[u8], stored_api_key: &[u8]) -> bool {
    timing_safe_eq(request_api_key, stored_api_key)
}

pub fn verify_reset_token(token: &[u8], expected_reset_token: &[u8]) -> bool {
    if token.len() != 64 {
        return false;
    }
    safe_compare(token, expected_reset_token)
}

pub fn public_id_matches(id: &str, expected_id: &str) -> bool {
    id == expected_id
}

pub fn token_shape_looks_valid(token: &str) -> bool {
    token.len() == 32 && token != ""
}
