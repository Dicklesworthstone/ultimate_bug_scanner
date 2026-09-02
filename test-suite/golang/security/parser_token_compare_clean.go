// GH #85 regression fixture (Go): ordinary parser/domain vocabulary must not be
// treated as secret material by the constant-time comparison detector. Every
// comparison here is a parser, layout, or schema check, never secret material.
package parser

import "strings"

var targetSigs = map[string]string{
	"asyncio.create_task": "asyncio_task",
}

func FindLayoutMarker(line string) bool {
	token := strings.Fields(line)
	candidate := ""
	if len(token) > 0 {
		candidate = token[0]
	}
	return candidate == "BR2"
}

func IsPageBreak(token string) bool {
	return token == "PAGE_BREAK" || token == "FF"
}

func GuardAllows(token string) bool {
	// A shell-command tokenizer: `rm` is a command word, not a credential.
	if token == "rm" {
		return false
	}
	return true
}

func SessionMatches(sessionID, expected string) bool {
	return sessionID == expected
}

func SignatureFormatIsDetached(signatureFormat string) bool {
	return signatureFormat == "detached"
}

func CredentialKindIsCertificate(credentialType string) bool {
	return credentialType == "certificate"
}

func JWTHeaderIsJOSE(jwtHeader string) bool {
	return jwtHeader == "JOSE"
}

func MapKeyPresent(key string, keys []string) bool {
	for _, entry := range keys {
		if entry == key {
			return true
		}
	}
	return false
}
