package security

import (
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

func trustDecodeOnly(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
	return claims, err
}

func acceptAnySigningMethod(tokenString string, secret []byte) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
}

func acceptAnySigningMethodWithClaims(tokenString string, secret []byte) (*jwt.Token, error) {
	claims := jwt.MapClaims{}
	return jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
}

func acceptValidMethodWithoutIssuerAudience(tokenString string, secret []byte) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
}

func createNoneAlgorithmToken(claims jwt.Claims) *jwt.Token {
	return jwt.NewWithClaims(jwt.SigningMethodNone, claims)
}

func parseWithoutClaimsValidation(tokenString string, secret []byte) (*jwt.Token, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	return parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secret, nil
	})
}
