// GH #91 regression fixtures: golang suppression divergence pair (bead A7).
// Each function here triggers a native ubs-golang.sh finding that the sibling
// suppression_buggy.go suppresses with an inline ignore marker in a distinct
// placement: trailing, previous-line, multi-line statement,
// formatter-relocated first line inside a block, and rule-scoped.
// This twin carries no markers, so every finding must be reported.

package suppression

import (
	"fmt"
	mathrand "math/rand"
	"net/http"
)

// Placement 1 (trailing): the marker rides the flagged declaration itself.
func trailingMarkerAssignment() string {
	apiKey := "ak_live_9f2c7b61d4e8a5c3"
	return apiKey
}

// Placement 2 (previous-line): the marker sits on the line directly above the
// flagged redirect sink.
func prevLineRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.Header.Get("X-Next-URL"), http.StatusFound)
}

// Placement 3 (multi-line statement): the flagged assignment opens a
// statement that continues onto the next physical line, so the trailing
// marker added in the twin sits on the opening line of a multi-line
// statement.
func multilineStatementAssignment() string {
	apiKeyExtended := "ak_live_9f2c7b61d4e8a5c3" +
		"-extended"
	return apiKeyExtended
}

// Placement 4 (formatter-relocated): formatters push a trailing marker off
// the block-opening line to the first line inside the block.
func relocatedCookie(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("X-Session-Id")
	if sid != "" {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Secure: false, HttpOnly: false})
	}
}

// Placement 5 (rule-scoped): the marker names the single rule it suppresses.
func scopedRandomToken() string {
	token := fmt.Sprintf("%d", mathrand.Int63())
	return token
}
