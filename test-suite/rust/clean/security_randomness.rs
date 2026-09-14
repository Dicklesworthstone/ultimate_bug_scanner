use rand::Rng;
use rand_core::{OsRng, RngCore};

pub fn create_session_token() -> String {
    let mut bytes = [0_u8; 32];
    if getrandom::getrandom(&mut bytes).is_err() {
        return String::new();
    }
    hex::encode(bytes)
}

pub fn csrf_nonce() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::encode(bytes)
}

pub fn api_key_from_system_random() -> String {
    let rng = ring::rand::SystemRandom::new();
    match ring::rand::generate::<[u8; 32]>(&rng) {
        Ok(generated) => hex::encode(generated.expose()),
        Err(_) => String::new(),
    }
}

pub fn request_id_for_logs() -> u32 {
    rand::thread_rng().gen_range(0..100)
}

pub fn token_from_thread_rng() -> [u8; 32] {
    rand::rng().random()
}

pub fn token_from_random() -> [u8; 32] {
    rand::random()
}

pub fn doc_comment_mentions_only() -> &'static str {
    "A token should not use fastrand::u64(..), but this is documentation text."
}
