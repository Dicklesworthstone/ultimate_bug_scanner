package security

import (
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

func verifyHMACToken(tokenString string, secret []byte) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secret, nil
	}, jwt.WithIssuer("https://issuer.example.com"), jwt.WithAudience("api://example"))
}

func verifyHMACClaims(tokenString string, secret []byte) (*jwt.Token, error) {
	claims := jwt.MapClaims{}
	return jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secret, nil
	}, jwt.WithIssuer("https://issuer.example.com"), jwt.WithAudience("api://example"))
}

func verifyWithValidMethods(tokenString string, secret []byte) (*jwt.Token, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer("https://issuer.example.com"),
		jwt.WithAudience("api://example"),
	)
	return parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
}
