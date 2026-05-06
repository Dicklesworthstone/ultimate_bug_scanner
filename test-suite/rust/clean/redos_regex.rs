use regex::{Regex, RegexSet};
use std::collections::HashMap;

struct Query<T>(T);

fn allowed_regex_pattern(value: &str) -> &'static str {
    match value {
        "email" => r"^[^@]+@example\.com$",
        "status" => r"^(active|archived)$",
        _ => r"^$",
    }
}

fn escaped_query_regex(Query(params): Query<HashMap<String, String>>) -> Regex {
    let raw = params.get("pattern").cloned().unwrap_or_default();
    let escaped = regex::escape(&raw);
    Regex::new(&escaped).unwrap()
}

fn allowlisted_regex(Query(params): Query<HashMap<String, String>>) -> Regex {
    let raw = params.get("kind").cloned().unwrap_or_default();
    let pattern = allowed_regex_pattern(&raw);
    Regex::new(pattern).unwrap()
}

fn fixed_regex_set() -> RegexSet {
    RegexSet::new([r"^(active|archived)$", r"^[a-z0-9_-]+$"]).unwrap()
}
