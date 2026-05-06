use regex::{Regex, RegexSet};
use std::collections::HashMap;

struct Path<T>(T);
struct Query<T>(T);

struct Request;

impl Request {
    fn query(&self, _name: &str) -> Option<String> {
        Some("(a+)+$".to_string())
    }
}

fn query_regex(Query(params): Query<HashMap<String, String>>) -> Regex {
    let pattern = params.get("pattern").cloned().unwrap_or_default();
    Regex::new(&pattern).unwrap()
}

fn path_regex(Path(tenant): Path<String>) -> Regex {
    regex::RegexBuilder::new(&tenant).build().unwrap()
}

fn header_regex_set(req: Request) -> RegexSet {
    let pattern = req.query("filter").unwrap_or_default();
    RegexSet::new([pattern]).unwrap()
}

fn formatted_regex(Query(params): Query<HashMap<String, String>>) -> Regex {
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    Regex::new(&format!("^{prefix}:[a-z0-9_-]+$")).unwrap()
}
