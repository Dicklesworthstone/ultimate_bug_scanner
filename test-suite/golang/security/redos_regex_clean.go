package security

import (
	"net/http"
	"regexp"
)

func allowedRegexpPattern(kind string) string {
	switch kind {
	case "email":
		return `^[^@]+@example\.com$`
	case "status":
		return `^(active|archived)$`
	default:
		return `^$`
	}
}

func escapedQueryRegex(r *http.Request) (*regexp.Regexp, error) {
	raw := r.URL.Query().Get("pattern")
	pattern := regexp.QuoteMeta(raw)
	return regexp.Compile(pattern)
}

func allowlistedRegex(r *http.Request) *regexp.Regexp {
	raw := r.URL.Query().Get("kind")
	pattern := allowedRegexpPattern(raw)
	return regexp.MustCompile(pattern)
}

func fixedPattern(value string) bool {
	matched, _ := regexp.MatchString(`^(active|archived)$`, value)
	return matched
}
