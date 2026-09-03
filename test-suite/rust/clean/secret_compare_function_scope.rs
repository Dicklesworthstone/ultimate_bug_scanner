// PR #100 regression fixture: secret-comparison taint is FUNCTION-scoped.
//
// A security-sensitive assignment to a generic local name (`issue`, `value`)
// used to taint every later use of that name anywhere in the file, so ordinary
// domain comparisons in unrelated functions were reported as critical timing
// leaks. Each function below rebinds a name the first function taints; none of
// these comparisons touches secret material.

use subtle::ConstantTimeEq;

pub fn verify_reset_link(auth_token: &str, expected: &str) -> bool {
    let issue = auth_token;
    issue.as_bytes().ct_eq(expected.as_bytes()).into()
}

pub fn is_tracked_issue_kind(issue: &str) -> bool {
    issue == "bug"
}

pub fn marker_matches(line: &str) -> bool {
    let issue = line.trim();
    issue == "END_OF_REPORT"
}

pub struct Report {
    kind: String,
}

impl Report {
    pub fn seal(&self, api_key: &str, expected: &str) -> bool {
        let value = api_key;
        value.as_bytes().ct_eq(expected.as_bytes()).into()
    }

    pub fn is_summary(&self, value: &str) -> bool {
        self.kind == value
    }
}

pub fn one_line_scope(line: &str) -> bool { let value = line; value == "OK" }
