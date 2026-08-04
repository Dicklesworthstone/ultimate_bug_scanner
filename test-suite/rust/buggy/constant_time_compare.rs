use std::collections::BTreeMap;

pub fn parser_candidate_matches(token: &str) -> bool {
    let candidate = token;
    candidate == "BR2"
}

pub fn remember_auth_alias_without_comparing(auth_token: &str) -> usize {
    let shared = auth_token;
    shared.len()
}

pub fn parser_after_security_function(shared: &str) -> bool {
    shared == "PAGE"
}

pub fn shadow_secret_with_parser(auth_token: &str, parser_token: &str) -> bool {
    let candidate = auth_token;
    let candidate = parser_token;
    candidate == "BR2"
}

pub fn overwrite_secret_with_parser(auth_token: &str, parser_label: &str) -> bool {
    let mut candidate = auth_token;
    candidate = parser_label;
    candidate == "1."
}

pub fn ignored_auth_comparison(
    ignored_auth_token: &str,
    ignored_expected_auth_token: &str,
) -> bool {
    // ubs:ignore -- fixture proves an intentional local suppression.
    ignored_auth_token == ignored_expected_auth_token
}

pub fn inline_ignored_session_comparison(
    ignored_session_token: &str,
    ignored_expected_session_token: &str,
) -> bool {
    ignored_session_token != ignored_expected_session_token // ubs:ignore -- local suppression
}

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

pub fn verify_signature_inline(bare_signature: &str, expected_bare_signature: &str) -> bool {
    bare_signature == expected_bare_signature
}

pub fn verify_reset_token_after_shape_check(token: &str, expected_reset_token: &str) -> bool {
    token.len() == 64 && token == expected_reset_token
}

pub fn verify_mixed_safe_and_unsafe_comparisons(
    provided_signature: &[u8],
    expected_signature: &[u8],
    provided_reset_token: &str,
    expected_reset_token: &str,
) -> bool {
    provided_signature.ct_eq(expected_signature).into()
        && provided_reset_token == expected_reset_token
}

pub fn verify_session_token_alias(
    provided_session_token: &str,
    expected_session_token: &str,
) -> bool {
    let alias_candidate = provided_session_token;
    alias_candidate == expected_session_token
}

pub fn verify_api_key_header(headers: &BTreeMap<String, String>, expected: &str) -> bool {
    let header_candidate = headers.get("X-API-Key").map(String::as_str).unwrap_or("");
    header_candidate == expected
}

pub fn verify_jwt_secret(direct_jwt_secret: &str, expected_direct_jwt_secret: &str) -> bool {
    direct_jwt_secret == expected_direct_jwt_secret
}

pub fn verify_stored_credential(
    direct_credential: &str,
    expected_direct_credential: &str,
) -> bool {
    direct_credential == expected_direct_credential
}

pub fn verify_conditional_session_token(
    page: usize,
    provided_session_token: &str,
    fallback_session_token: &str,
    expected: &str,
) -> bool {
    let conditional_candidate = if page == 1 {
        provided_session_token
    } else {
        fallback_session_token
    };
    conditional_candidate == expected
}

pub fn verify_csrf_multiline(req: &Request, expected_multiline_csrf: &str) -> bool {
    req.csrf_token
        == expected_multiline_csrf
}

pub fn verify_bearer_with_trailing_operator(
    trailing_bearer_token: &str,
    expected: &str,
) -> bool {
    trailing_bearer_token ==
        expected
}

pub fn verify_trimmed_session_token(
    provided_session_token: &str,
    expected_trimmed_value: &str,
) -> bool {
    let trim_candidate = provided_session_token;
    trim_candidate
        .trim()
        == expected_trimmed_value
}

pub fn verify_after_conditional_public_overwrite(
    use_public: bool,
    auth_token: &str,
    public_value: &str,
    expected: &str,
) -> bool {
    let mut branch_candidate = auth_token;
    if use_public {
        branch_candidate = public_value;
    }
    branch_candidate == expected
}

pub fn verify_after_public_shadow(
    auth_token: &str,
    public_value: &str,
    expected: &str,
) -> bool {
    let shadowed_candidate = auth_token;
    {
        let shadowed_candidate = public_value;
        let _public_match = shadowed_candidate == "BR2";
    }
    shadowed_candidate == expected
}

pub fn verify_secret_shadow_only(
    public_value: &str,
    auth_token: &str,
    expected: &str,
) -> bool {
    let restored_candidate = public_value;
    {
        let restored_candidate = auth_token;
        let _secret_match = restored_candidate == expected;
    }
    restored_candidate == public_value
}

pub fn verify_csrf_with_intervening_comment(
    provided_csrf_token: &str,
    expected_csrf_token: &str,
) -> bool {
    provided_csrf_token
        // The operator may be separated from its operand in formatted Rust.
        != expected_csrf_token
}

pub fn verify_credential_parenthesized_multiline(
    provided_credential: &str,
    parenthesized_credential: &str,
) -> bool {
    (
        provided_credential
            == parenthesized_credential
    )
}

pub fn compare_auth_then_compare_boolean(
    auth_token: &str,
    expected_auth_token: &str,
    expected_boolean: bool,
) -> bool {
    let is_auth_match = auth_token == expected_auth_token;
    is_auth_match == expected_boolean
}

pub fn active_auth_comparison_after_ignored_function(
    active_auth_token: &str,
    active_expected_auth_token: &str,
) -> bool {
    active_auth_token == active_expected_auth_token
}

pub fn verify_mixed_ring_and_credential(
    left: &[u8],
    right: &[u8],
    provided_credential: &str,
    stored_credential: &str,
) -> bool {
    ring::constant_time::verify_slices_are_equal(left, right).is_ok()
        && provided_credential == stored_credential
}

pub fn verify_mixed_memcmp_and_jwt_secret(
    left: &[u8],
    right: &[u8],
    provided_jwt_secret: &str,
    expected_jwt_secret: &str,
) -> bool {
    crypto_memcmp(left, right)
        || provided_jwt_secret != expected_jwt_secret
}

pub fn compare_unsafe_conditional_then_boolean(
    enabled: bool,
    conditional_auth_secret: &str,
    conditional_auth_expected: &str,
    expected_boolean: bool,
) -> bool {
    let unsafe_conditional_result = if enabled {
        conditional_auth_secret == conditional_auth_expected
    } else {
        false
    };
    unsafe_conditional_result == expected_boolean
}

pub fn verify_safe_sibling_argument_does_not_hide_secret(
    left: &[u8],
    right: &[u8],
    backup_secret: &str,
    expected_backup: &str,
) -> bool {
    audit(
        crypto_memcmp(left, right),
        backup_secret == expected_backup,
    )
}

pub fn verify_bitwise_safe_and_unsafe_mix(
    left: &[u8],
    right: &[u8],
    backup_secret: &str,
    expected_backup: &str,
) -> bool {
    crypto_memcmp(left, right) & (backup_secret == expected_backup)
}

pub fn verify_long_fluent_auth_alias(auth_token: &str, expected_fluent: &str) -> bool {
    let fluent_candidate = auth_token;
    fluent_candidate
        .trim()
        .trim()
        .trim()
        .trim()
        .trim()
        .trim()
        .trim()
        == expected_fluent
}
