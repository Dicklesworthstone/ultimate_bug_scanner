// Suppression fixture pair (bead A7, GH #91) for the JS/TS module.
//
// Every finding below carries a suppression marker in one of the four
// honored arrangements:
//   1. trailing the flagged line,
//   2. on the line immediately above the flagged statement,
//   3. on a middle physical line of a multi-line statement,
//   4. formatter-relocated onto the first line inside a block that the
//      flagged statement opens.
// Scanning this file must report ZERO findings. The twin file
// suppression_buggy_nomarkers.js keeps every line aligned but strips the
// markers, so scanning it must report the findings.

// ---------------------------------------------------------------------------
// Arrangement 1 -- trailing marker: the dynamic-code evaluation call is a
// critical finding for the heuristic pass and for ast-grep rule js.eval-call.
// ---------------------------------------------------------------------------
function runUserCode(userCode) {
  eval(userCode); // ubs:ignore[js.eval-call] -- trailing marker arrangement
}

// ---------------------------------------------------------------------------
// Arrangement 2 -- previous-line marker: a literal assigned to a
// secret-named constant is a critical hardcoded-secret finding.
// ---------------------------------------------------------------------------
// ubs:ignore -- previous-line marker arrangement
const API_SECRET = "sk-live-suppression-fixture-0001";

// ---------------------------------------------------------------------------
// Arrangement 3 -- multi-line statement middle: the token comparison sits on
// the middle physical line of a multi-line `if (...)` condition.
// ---------------------------------------------------------------------------
function compareTokens(authToken, expectedToken) {
  if (
    authToken !== expectedToken // ubs:ignore -- multi-line middle marker
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
    // ubs:ignore -- formatter-relocated marker arrangement
    return false;
  }
  return true;
}
