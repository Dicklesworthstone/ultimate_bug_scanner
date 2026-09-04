// Suppression fixture pair (bead A7, GH #91) for the JS/TS module.
//
// Twin of suppression_buggy.js: every line is aligned with the markered
// fixture but the suppression markers are stripped, so the findings that
// the markered file suppresses must be reported here. The four marker
// arrangements exercised are:
//   1. trailing the flagged line,
//   2. on the line immediately above the flagged statement,
//   3. on a middle physical line of a multi-line statement,
//   4. formatter-relocated onto the first line inside a block that the
//      flagged statement opens.
// A scan of this file must report at least two findings.

// ---------------------------------------------------------------------------
// Arrangement 1 -- trailing marker: the dynamic-code evaluation call is a
// critical finding for the heuristic pass and for ast-grep rule js.eval-call.
// ---------------------------------------------------------------------------
function runUserCode(userCode) {
  eval(userCode); // trailing marker arrangement (marker stripped here)
}

// ---------------------------------------------------------------------------
// Arrangement 2 -- previous-line marker: a literal assigned to a
// secret-named constant is a critical hardcoded-secret finding.
// ---------------------------------------------------------------------------
// previous-line marker arrangement (marker stripped here)
const API_SECRET = "sk-live-suppression-fixture-0001";

// ---------------------------------------------------------------------------
// Arrangement 3 -- multi-line statement middle: the token comparison sits on
// the middle physical line of a multi-line `if (...)` condition.
// ---------------------------------------------------------------------------
function compareTokens(authToken, expectedToken) {
  if (
    authToken !== expectedToken // multi-line middle marker (stripped here)
  ) {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Arrangement 4 -- formatter-relocated marker: the flagged `if (...) {`
// opens a block and the marker moved to its first line, as formatters do.
// ---------------------------------------------------------------------------
function checkSession(sessionToken, expectedSessionToken) {
  if (sessionToken !== expectedSessionToken) {
    // formatter-relocated marker arrangement (marker stripped here)
    return false;
  }
  return true;
}
