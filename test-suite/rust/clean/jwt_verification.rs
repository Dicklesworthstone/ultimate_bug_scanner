use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

#[derive(Debug)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub aud: String,
    pub iss: String,
}

pub fn verify_token(token: &str, key: &DecodingKey) -> jsonwebtoken::errors::Result<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["frontend"]);
    validation.set_issuer(&["issuer"]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    decode::<Claims>(token, key, &validation).map(|data| data.claims)
}

pub fn verify_rsa_token(token: &str, key: &DecodingKey) -> jsonwebtoken::errors::Result<Claims> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.validate_aud = true;
    validation.set_audience(&["backend"]);
    validation.set_issuer(&["issuer"]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    decode::<Claims>(token, key, &validation).map(|data| data.claims)
}

pub(crate) async fn verify_scoped_token(
    token: &str,
    key: &DecodingKey,
) -> jsonwebtoken::errors::Result<Claims> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["service"]);
    validation.set_issuer(&["issuer"]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    decode::<Claims>(token, key, &validation).map(|data| data.claims)
}

pub fn documentation_mentions_do_not_count() -> usize {
    let decode_docs = "dangerous::insecure_decode::<Claims>(token)";
    let validation_docs = "Validation { validate_exp: false, validate_aud: false }";
    /*
       This comment documents what not to do:
       validation.insecure_disable_signature_validation();
    */
    decode_docs.len() + validation_docs.len()
}
