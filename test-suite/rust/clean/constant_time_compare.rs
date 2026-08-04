use std::collections::BTreeMap;
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

pub fn parser_candidate_matches(token: &str) -> bool {
    let candidate = token;
    candidate == "BR2"
}

pub fn public_nonce_matches(public_nonce: &str, expected_nonce: &str) -> bool {
    public_nonce == expected_nonce
}

pub fn jwt_claims_match(jwt_claims: &str, expected_claims: &str) -> bool {
    jwt_claims == expected_claims
}

pub fn mac_address_matches(mac_address: &str, expected_mac: &str) -> bool {
    mac_address == expected_mac
}

pub fn formatted_parser_label_matches(label: &str) -> bool {
    let expected = format!("session_token");
    label == expected
}

pub fn file_digest_matches(file_digest: &str, expected_digest: &str) -> bool {
    file_digest == expected_digest
}

pub fn verify_with_ring(left: &[u8], right: &[u8]) -> bool {
    ring::constant_time::verify_slices_are_equal(left, right).is_ok()
}

pub fn verify_with_crypto_memcmp(left: &[u8], right: &[u8]) -> bool {
    crypto_memcmp(left, right)
}

#[derive(PartialEq)]
pub enum SessionState {
    Active,
}

#[derive(PartialEq)]
pub enum VerificationResult {
    Valid,
}

#[derive(PartialEq)]
pub enum AuthStatus {
    Authenticated,
}

#[derive(PartialEq)]
pub enum TokenKind {
    Word,
}

pub struct Evidence {
    raw_text: String,
    page_index: usize,
}

pub struct Word {
    word_id: usize,
}

pub fn parser_domain_comparisons(
    evidence: &Evidence,
    word: &Word,
    parser_token: &str,
    expected_word_id: usize,
    type_signature: &str,
    expected_type_signature: &str,
    payload_digest: &str,
    expected_digest: &str,
    source_hash: &str,
    expected_source_hash: &str,
    session_state: SessionState,
    verification_result: VerificationResult,
    auth_status: AuthStatus,
    parser_kind: TokenKind,
) -> bool {
    let last_page_index = 3;
    parser_token == "1."
        || evidence.raw_text.trim() == "1."
        || evidence.page_index != last_page_index
        || word.word_id == expected_word_id
        || type_signature == expected_type_signature
        || payload_digest == expected_digest
        || source_hash == expected_source_hash
        || session_state == SessionState::Active
        || verification_result == VerificationResult::Valid
        || auth_status == AuthStatus::Authenticated
        || parser_kind == TokenKind::Word
}

pub fn parser_security_metadata_matches(
    credential_schema: &str,
    expected_credential_schema: &str,
    authorization_policy: &str,
    expected_authorization_policy: &str,
) -> bool {
    credential_schema == expected_credential_schema
        || authorization_policy == expected_authorization_policy
}

pub fn public_signature_registry_matches(
    schema_registry: &std::collections::BTreeMap<String, String>,
    expected: &str,
) -> bool {
    schema_registry.get("X-Signature").map(String::as_str) == Some(expected)
}

pub fn unconditional_public_overwrite_is_clean(
    auth_token: &str,
    public_value: &str,
) -> bool {
    let mut candidate = auth_token;
    candidate = public_value;
    candidate == "BR2"
}

pub fn secret_inner_shadow_does_not_taint_outer_value(
    public_value: &str,
    auth_token: &str,
) -> bool {
    let candidate = public_value;
    {
        let candidate = auth_token;
        let _secret_shape = candidate.len();
    }
    candidate == public_value
}

pub fn safe_conditional_boolean_is_not_secret(
    enabled: bool,
    auth_token: &[u8],
    expected: &[u8],
    expected_match: bool,
) -> bool {
    let is_match = if enabled {
        auth_token.ct_eq(expected).into()
    } else {
        false
    };
    is_match == expected_match
}

pub fn cache_auth_alias_without_comparing(auth_token: &str) -> usize {
    let candidate = auth_token;
    candidate.len()
}

// ubs:ignore -- function-boundary suppression must not leak prior taint.
pub fn parser_after_ignored_function_boundary(candidate: &str) -> bool {
    candidate == "BR2"
}

pub fn comparison_tokens_inside_data_are_not_operators(label: &str) -> bool {
    let rendered = format!("auth_token == {}", label);
    let raw = r#"authorization != expected"#;
    /* csrf_token == expected_csrf_token */
    rendered.len() == raw.len()
}

pub fn public_multiline_parser_token(parser_token: &str) -> bool {
    parser_token ==
        "1."
}

pub fn same_scope_parser_shadow_is_clean(auth_token: &str, parser_token: &str) -> bool {
    let candidate = auth_token;
    let candidate = parser_token;
    candidate == "BR2"
}

pub fn parser_lookup_string_is_data(row: &BTreeMap<String, String>) -> bool {
    let value = row
        .get("credential_type")
        .map(String::as_str)
        .unwrap_or("");
    value == "ABS"
}

pub fn ordinary_string_comparison_is_data(label: &str) -> bool {
    let expected = "auth_token == expected_auth_token";
    label == expected
}

pub fn raw_string_comparison_is_data(label: &str) -> bool {
    let expected = r#"webhook_signature != expected_signature"#;
    label == expected
}

pub fn byte_raw_string_comparison_is_data(label: &[u8]) -> bool {
    let expected: &[u8] = br##"provided_credential == stored_credential"##;
    label == expected
}

/*
pub fn fake_auth_comparison(auth_token: &str, expected_auth_token: &str) -> bool {
    auth_token == expected_auth_token
}
*/
pub fn parser_after_block_comment(parser_token: &str) -> bool {
    parser_token == "BR2"
}

pub fn inline_block_comment_is_data(parser_token: &str) -> bool {
    let value = parser_token /* provided_credential == stored_credential */;
    value == "1."
}

pub fn parser_multiline_comparison(
    parser_token: &str,
    expected_parser_token: &str,
) -> bool {
    parser_token
        == expected_parser_token
}

pub fn combined_ring_and_memcmp(left: &[u8], right: &[u8]) -> bool {
    ring::constant_time::verify_slices_are_equal(left, right).is_ok()
        && crypto_memcmp(left, right)
}

pub fn compare_safe_result_boolean(
    left: &[u8],
    right: &[u8],
    expected_boolean: bool,
) -> bool {
    let verified = ring::constant_time::verify_slices_are_equal(left, right).is_ok();
    verified == expected_boolean
}

pub fn ordinary_block_public_overwrite_is_clean(
    auth_token: &str,
    public_value: &str,
) -> bool {
    let mut ordinary_block_candidate = auth_token;
    {
        ordinary_block_candidate = public_value;
    }
    ordinary_block_candidate == "BR2"
}

pub fn character_literal_brace_is_not_scope(
    auth_token: &str,
    public_value: &str,
) -> bool {
    let _marker = '{';
    let mut char_literal_candidate = auth_token;
    char_literal_candidate = public_value;
    char_literal_candidate == "BR2"
}

pub fn inverted_safe_conditional_boolean_is_clean(
    enabled: bool,
    auth_token: &[u8],
    expected: &[u8],
    expected_match: bool,
) -> bool {
    let inverted_match = if enabled {
        false
    } else {
        auth_token.ct_eq(expected).into()
    };
    inverted_match == expected_match
}

pub fn match_safe_boolean_is_clean(
    enabled: bool,
    auth_token: &[u8],
    expected: &[u8],
    expected_match: bool,
) -> bool {
    let matched = match enabled {
        true => auth_token.ct_eq(expected).into(),
        false => false,
    };
    matched == expected_match
}

pub fn multiline_ignored_auth_comparison(auth_token: &str, expected: &str) -> bool {
    // ubs:ignore -- reviewed exception applies to the reconstructed statement.
    auth_token
        == expected
}
