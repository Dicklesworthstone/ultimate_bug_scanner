package security

import (
	"fmt"
	"net/http"
	"net/url"
)

type resetMailer interface {
	Send(to string, html string) error
}

func passwordResetURL(r *http.Request, token string) string {
	host := r.Host
	return fmt.Sprintf("https://%s/reset?token=%s", host, url.QueryEscape(token))
}

func forwardedVerificationURL(r *http.Request, token string) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return (&url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     "/verify",
		RawQuery: "token=" + url.QueryEscape(token),
	}).String()
}

func sendResetEmail(r *http.Request, mailer resetMailer, token string) error {
	host := r.Header.Get("Host")
	resetLink := "https://" + host + "/account/reset?token=" + url.QueryEscape(token)
	return mailer.Send("user@example.com", `<a href="`+resetLink+`">Reset password</a>`)
}

func resetURLWithValidationTooLate(r *http.Request, token string) string {
	host := r.Host
	resetLink := "https://" + host + "/reset?token=" + url.QueryEscape(token)
	if !map[string]bool{"app.example.com": true}[host] {
		return ""
	}
	return resetLink
}

func canonicalURLFromRequest(r *http.Request, pathname string) string {
	origin := "https://" + r.Host
	return origin + pathname
}
