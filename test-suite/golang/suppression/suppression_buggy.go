// GH #91 regression fixtures: golang suppression divergence pair (bead A7).
// Every function below triggers a native ubs-golang.sh finding that is
// suppressed here by an ubs:ignore marker in a distinct placement: trailing,
// previous-line, multi-line statement, formatter-relocated first line inside
// a block, and rule-scoped. The sibling suppression_buggy_nomarkers.go
// carries the same code without markers, so every finding must be reported
// there and suppressed here.

package suppression

import (
	"fmt"
	mathrand "math/rand"
	"net/http"
)

// Placement 1 (trailing): the marker rides the flagged declaration itself.
func trailingMarkerAssignment() string {
	apiKey := "ak_live_9f2c7b61d4e8a5c3" // ubs:ignore -- fixture: trailing placement
	return apiKey
}

// Placement 2 (previous-line): the marker sits on the line directly above the
// flagged redirect sink.
func prevLineRedirect(w http.ResponseWriter, r *http.Request) {
	// ubs:ignore -- fixture: previous-line placement
	http.Redirect(w, r, r.Header.Get("X-Next-URL"), http.StatusFound)
}

// Placement 3 (multi-line statement): the flagged assignment opens a
// statement that continues onto the next physical line, so the trailing
// marker sits on the opening line of a multi-line statement.
func multilineStatementAssignment() string {
	apiKeyExtended := "ak_live_9f2c7b61d4e8a5c3" + // ubs:ignore -- fixture: multi-line statement placement
		"-extended"
	return apiKeyExtended
}

// Placement 4 (formatter-relocated): formatters push a trailing marker off
// the block-opening line to the first line inside the block.
func relocatedCookie(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("X-Session-Id")
	if sid != "" {
		// ubs:ignore -- fixture: formatter-relocated first-line-in-block placement
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Secure: false, HttpOnly: false})
	}
}

// Placement 5 (rule-scoped): the marker names the single rule it suppresses.
func scopedRandomToken() string {
	token := fmt.Sprintf("%d", mathrand.Int63()) // ubs:ignore[go.crypto.rand] -- fixture: rule-scoped placement
	return token
}
