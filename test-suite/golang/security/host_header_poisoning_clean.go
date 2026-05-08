package security

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const publicBaseURL = "https://app.example.com"

var allowedLinkHosts = map[string]bool{
	"app.example.com":      true,
	"accounts.example.com": true,
}

func trustedOriginFromHost(rawHost string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(rawHost))
	if !allowedLinkHosts[host] {
		return "", errors.New("untrusted host")
	}
	return "https://" + host, nil
}

func passwordResetURLFromConfig(_ *http.Request, token string) string {
	return publicBaseURL + "/reset?token=" + url.QueryEscape(token)
}

func forwardedVerificationURLAllowed(r *http.Request, token string) (string, error) {
	rawHost := r.Header.Get("X-Forwarded-Host")
	if rawHost == "" {
		rawHost = r.Host
	}
	origin, err := trustedOriginFromHost(rawHost)
	if err != nil {
		return "", err
	}
	return origin + "/verify?token=" + url.QueryEscape(token), nil
}

func auditRequestHost(r *http.Request) bool {
	host := r.Host
	return host != ""
}

func literalHostAfterAudit(pathname string) string {
	host := "app.example.com"
	return "https://" + host + pathname
}
