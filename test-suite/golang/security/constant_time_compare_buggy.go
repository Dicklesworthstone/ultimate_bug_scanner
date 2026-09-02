package security

import "net/http"

type account struct {
	ResetToken string
	APIKey     string
}

func verifyWebhookSignature(r *http.Request, expectedSignature string) bool {
	providedSignature := r.Header.Get("X-Signature")
	return providedSignature == expectedSignature
}

func verifyAPIKey(requestAPIKey string, storedAPIKey string) bool {
	if requestAPIKey != storedAPIKey {
		return false
	}
	return true
}

func verifyCSRF(r *http.Request, sessionCSRFToken string) bool {
	csrfToken := r.FormValue("csrf_token")
	return csrfToken == sessionCSRFToken
}

func verifyResetToken(token string, user account) bool {
	return token == user.ResetToken
}

func verifyBearerToken(r *http.Request, expectedToken string) bool {
	authorization := r.Header.Get("Authorization")
	return authorization == expectedToken
}

func rejectWrongResetToken(token string, user account) bool {
	return token != user.ResetToken
}

func verifySignatureInline(signature string, expectedSignature string) bool {
	return signature == expectedSignature
}

func verifyLengthGuardedResetToken(token string, expectedResetToken string) bool {
	return len(token) == 64 && token == expectedResetToken
}

// Positive control for #54: a genuine secret comparison whose sensitivity comes
// from the OPERAND identifiers (not from string data) must STILL be detected after
// the false-positive fix that ignores sensitive words inside string-literal contents.
// The identifiers carry a security qualifier (auth + token) because, since the
// GH #85 two-tier vocabulary, a bare parser-style `token` is deliberately not
// treated as secret material on its own (see parser_token_compare_clean.go).
func checkToken(gotAuthToken string, wantAuthToken string) bool {
	return gotAuthToken == wantAuthToken
}
