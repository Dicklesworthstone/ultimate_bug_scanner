package security

import (
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5"
)

func queryRegex(r *http.Request) (*regexp.Regexp, error) {
	pattern := r.URL.Query().Get("pattern")
	return regexp.Compile(pattern)
}

func routeRegex(r *http.Request) *regexp.Regexp {
	slug := chi.URLParam(r, "slug")
	return regexp.MustCompile(slug)
}

func headerMatch(req *http.Request, value string) bool {
	pattern := req.Header.Get("X-Filter")
	matched, _ := regexp.MatchString(pattern, value)
	return matched
}
