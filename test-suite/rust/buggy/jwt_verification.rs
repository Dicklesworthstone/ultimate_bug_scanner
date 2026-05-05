use jsonwebtoken::{dangerous_unsafe_decode, decode, Algorithm, DecodingKey, Validation};

#[derive(Debug)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub aud: String,
}

pub fn trust_decode_only(token: &str) -> jsonwebtoken::errors::Result<Claims> {
    jsonwebtoken::dangerous::insecure_decode::<Claims>(token).map(|data| data.claims)
}

pub fn trust_legacy_decode_only(token: &str) -> jsonwebtoken::errors::Result<Claims> {
    dangerous_unsafe_decode::<Claims>(token).map(|data| data.claims)
}

pub fn disable_signature_verification(
    token: &str,
    key: &DecodingKey,
) -> jsonwebtoken::errors::Result<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    decode::<Claims>(token, key, &validation).map(|data| data.claims)
}

pub fn disable_expiration_validation(
    token: &str,
    key: &DecodingKey,
) -> jsonwebtoken::errors::Result<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    decode::<Claims>(token, key, &validation).map(|data| data.claims)
}

pub fn disable_audience_validation(
    token: &str,
    key: &DecodingKey,
) -> jsonwebtoken::errors::Result<Claims> {
    let validation = Validation {
        validate_aud: false,
        ..Validation::new(Algorithm::HS256)
    };
    decode::<Claims>(token, key, &validation).map(|data| data.claims)
}

pub fn omit_issuer_and_audience_binding(
    token: &str,
    key: &DecodingKey,
) -> jsonwebtoken::errors::Result<Claims> {
    let validation = Validation::new(Algorithm::RS256);
    decode::<Claims>(token, key, &validation).map(|data| data.claims)
}

pub fn decode_with_neighboring_bound_validation(
    token: &str,
    key: &DecodingKey,
) -> jsonwebtoken::errors::Result<Claims> {
    let mut bound_validation = Validation::new(Algorithm::RS256);
    bound_validation.set_audience(&["frontend"]);
    bound_validation.set_issuer(&["issuer"]);
    bound_validation.set_required_spec_claims(&["exp", "iss", "aud"]);

    let loose_validation = Validation::new(Algorithm::RS256);
    decode::<Claims>(token, key, &loose_validation).map(|data| data.claims)
}
