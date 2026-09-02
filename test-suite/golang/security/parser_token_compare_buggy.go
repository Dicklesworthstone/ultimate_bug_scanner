// GH #85 positive control (Go): qualified security vocabulary must still
// trigger the constant-time comparison detector after the parser-vocabulary
// tightening. Every ==/!= below compares secret material and must be reported.
package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
)

var expectedAuthToken = os.Getenv("EXPECTED_AUTH_TOKEN")

func computeHMAC(payload []byte) string {
	mac := hmac.New(sha256.New, []byte("k"))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func CheckAPIKey(r *http.Request) bool {
	apiKey := r.Header.Get("X-API-Key")
	return apiKey == os.Getenv("API_KEY") // secret compared with ==
}

func CheckSessionToken(sessionToken, stored string) bool {
	return sessionToken == stored // secret compared with ==
}

func VerifyWebhook(payload []byte, providedSignature string) bool {
	expected := computeHMAC(payload)
	return providedSignature == expected // signature compared with ==
}

func CheckAuthToken(r *http.Request) bool {
	authToken := r.Header.Get("Authorization")
	if authToken != expectedAuthToken { // secret compared with !=
		return false
	}
	return true
}

func CheckPassword(password, storedHash string) bool {
	return password == storedHash // password compared with ==
}
