// PR #100 positive control: function-scoping the secret-comparison taint must
// not weaken same-function alias propagation, module-scope secrets, or direct
// secret comparisons.

static API_SECRET: &str = "replace-me";

pub fn same_function_alias(auth_token: &str, expected: &str) -> bool {
    let issue = auth_token;
    issue == expected
}

pub fn module_secret_reaches_every_function(candidate: &str) -> bool {
    candidate == API_SECRET
}

pub fn direct_secret_comparison(session_token: &str, expected_session_token: &str) -> bool {
    session_token == expected_session_token
}

pub struct Verifier;

impl Verifier {
    pub fn method_alias(&self, webhook_signature: &str, expected: &str) -> bool {
        let value = webhook_signature;
        value == expected
    }
}
